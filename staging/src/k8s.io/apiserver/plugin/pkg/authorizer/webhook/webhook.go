/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package webhook implements the authorizer.Authorizer interface using HTTP webhooks.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"

	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/wait"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authzconfig "k8s.io/apiserver/pkg/authorization/config"
	"k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/client-go/kubernetes/scheme"
	authorizationv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	// The maximum length of requester-controlled attributes to allow caching.
	maxControlledAttrCacheSize = 10000
)

// DefaultRetryBackoff returns the default backoff parameters for webhook retry.
func DefaultRetryBackoff() *wait.Backoff {
	backoff := webhook.DefaultRetryBackoffWithInitialDelay(500 * time.Millisecond)
	return &backoff
}

// Ensure Webhook implements the authorizer.Authorizer interface.
var _ authorizer.Authorizer = (*WebhookAuthorizer)(nil)

type subjectAccessReviewer interface {
	Create(context.Context, *authorizationv1.SubjectAccessReview, metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, int, error)
}

type WebhookAuthorizer struct {
	subjectAccessReview subjectAccessReviewer
	responseCache       *cache.LRUExpireCache
	authorizedTTL       time.Duration
	unauthorizedTTL     time.Duration
	retryBackoff        wait.Backoff
	decisionOnError     authorizer.Decision
	metrics             AuthorizerMetrics
	matchConditions     []authzconfig.WebhookMatchCondition
}

type evaluationActivation struct {
	request interface{}
}

// ResolveName returns a value from the activation by qualified name, or false if the name
// could not be found.
func (a *evaluationActivation) ResolveName(name string) (interface{}, bool) {
	switch name {
	case "request":
		return a.request, true
	default:
		return nil, false
	}
}

// Parent returns the parent of the current activation, may be nil.
// If non-nil, the parent will be searched during resolve calls.
func (a *evaluationActivation) Parent() interpreter.Activation {
	return nil
}

// NewFromInterface creates a WebhookAuthorizer using the given subjectAccessReview client
func NewFromInterface(subjectAccessReview authorizationv1client.AuthorizationV1Interface, authorizedTTL, unauthorizedTTL time.Duration, retryBackoff wait.Backoff, metrics AuthorizerMetrics) (*WebhookAuthorizer, error) {
	return newWithBackoff(&subjectAccessReviewV1Client{subjectAccessReview.RESTClient()}, authorizedTTL, unauthorizedTTL, retryBackoff, []authzconfig.WebhookMatchCondition{}, metrics)
}

// New creates a new WebhookAuthorizer from the provided kubeconfig file.
// The config's cluster field is used to refer to the remote service, user refers to the returned authorizer.
//
//	# clusters refers to the remote service.
//	clusters:
//	- name: name-of-remote-authz-service
//	  cluster:
//	    certificate-authority: /path/to/ca.pem      # CA for verifying the remote service.
//	    server: https://authz.example.com/authorize # URL of remote service to query. Must use 'https'.
//
//	# users refers to the API server's webhook configuration.
//	users:
//	- name: name-of-api-server
//	  user:
//	    client-certificate: /path/to/cert.pem # cert for the webhook plugin to use
//	    client-key: /path/to/key.pem          # key matching the cert
//
// For additional HTTP configuration, refer to the kubeconfig documentation
// https://kubernetes.io/docs/user-guide/kubeconfig-file/.
func New(config *rest.Config, version string, authorizedTTL, unauthorizedTTL time.Duration, retryBackoff wait.Backoff, matchConditions []authzconfig.WebhookMatchCondition) (*WebhookAuthorizer, error) {
	subjectAccessReview, err := subjectAccessReviewInterfaceFromConfig(config, version, retryBackoff)
	if err != nil {
		return nil, err
	}
	return newWithBackoff(subjectAccessReview, authorizedTTL, unauthorizedTTL, retryBackoff, matchConditions, AuthorizerMetrics{
		RecordRequestTotal:   noopMetrics{}.RecordRequestTotal,
		RecordRequestLatency: noopMetrics{}.RecordRequestLatency,
	})
}

// newWithBackoff allows tests to skip the sleep.
func newWithBackoff(subjectAccessReview subjectAccessReviewer, authorizedTTL, unauthorizedTTL time.Duration, retryBackoff wait.Backoff, matchConditions []authzconfig.WebhookMatchCondition, metrics AuthorizerMetrics) (*WebhookAuthorizer, error) {
	return &WebhookAuthorizer{
		subjectAccessReview: subjectAccessReview,
		responseCache:       cache.NewLRUExpireCache(8192),
		authorizedTTL:       authorizedTTL,
		unauthorizedTTL:     unauthorizedTTL,
		retryBackoff:        retryBackoff,
		decisionOnError:     authorizer.DecisionNoOpinion,
		metrics:             metrics,
		matchConditions:     matchConditions,
	}, nil
}

// Authorize makes a REST request to the remote service describing the attempted action as a JSON
// serialized api.authorization.v1beta1.SubjectAccessReview object. An example request body is
// provided below.
//
//	{
//	  "apiVersion": "authorization.k8s.io/v1beta1",
//	  "kind": "SubjectAccessReview",
//	  "spec": {
//	    "resourceAttributes": {
//	      "namespace": "kittensandponies",
//	      "verb": "GET",
//	      "group": "group3",
//	      "resource": "pods"
//	    },
//	    "user": "jane",
//	    "group": [
//	      "group1",
//	      "group2"
//	    ]
//	  }
//	}
//
// The remote service is expected to fill the SubjectAccessReviewStatus field to either allow or
// disallow access. A permissive response would return:
//
//	{
//	  "apiVersion": "authorization.k8s.io/v1beta1",
//	  "kind": "SubjectAccessReview",
//	  "status": {
//	    "allowed": true
//	  }
//	}
//
// To disallow access, the remote service would return:
//
//	{
//	  "apiVersion": "authorization.k8s.io/v1beta1",
//	  "kind": "SubjectAccessReview",
//	  "status": {
//	    "allowed": false,
//	    "reason": "user does not have read access to the namespace"
//	  }
//	}
//
// TODO(mikedanese): We should eventually support failing closed when we
// encounter an error. We are failing open now to preserve backwards compatible
// behavior.
func (w *WebhookAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (decision authorizer.Decision, reason string, err error) {
	r := &authorizationv1.SubjectAccessReview{}
	if user := attr.GetUser(); user != nil {
		r.Spec = authorizationv1.SubjectAccessReviewSpec{
			User:   user.GetName(),
			UID:    user.GetUID(),
			Groups: user.GetGroups(),
			Extra:  convertToSARExtra(user.GetExtra()),
		}
	}

	if attr.IsResourceRequest() {
		r.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   attr.GetNamespace(),
			Verb:        attr.GetVerb(),
			Group:       attr.GetAPIGroup(),
			Version:     attr.GetAPIVersion(),
			Resource:    attr.GetResource(),
			Subresource: attr.GetSubresource(),
			Name:        attr.GetName(),
		}
	} else {
		r.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{
			Path: attr.GetPath(),
			Verb: attr.GetVerb(),
		}
	}
	// Process Match Conditions before calling the webhook
	// TODO: check cache
	matches, err := w.Match(ctx, r)
	if err != nil {
		return w.decisionOnError, "", err
	}
	if !matches {
		return authorizer.DecisionNoOpinion, "", nil
	}

	key, err := json.Marshal(r.Spec)
	if err != nil {
		return w.decisionOnError, "", err
	}
	if entry, ok := w.responseCache.Get(string(key)); ok {
		r.Status = entry.(authorizationv1.SubjectAccessReviewStatus)
	} else {
		var result *authorizationv1.SubjectAccessReview
		// WithExponentialBackoff will return SAR create error (sarErr) if any.
		if err := webhook.WithExponentialBackoff(ctx, w.retryBackoff, func() error {
			var sarErr error
			var statusCode int

			start := time.Now()
			result, statusCode, sarErr = w.subjectAccessReview.Create(ctx, r, metav1.CreateOptions{})
			latency := time.Since(start)

			if statusCode != 0 {
				w.metrics.RecordRequestTotal(ctx, strconv.Itoa(statusCode))
				w.metrics.RecordRequestLatency(ctx, strconv.Itoa(statusCode), latency.Seconds())
				return sarErr
			}

			if sarErr != nil {
				w.metrics.RecordRequestTotal(ctx, "<error>")
				w.metrics.RecordRequestLatency(ctx, "<error>", latency.Seconds())
			}

			return sarErr
		}, webhook.DefaultShouldRetry); err != nil {
			klog.Errorf("Failed to make webhook authorizer request: %v", err)
			return w.decisionOnError, "", err
		}

		r.Status = result.Status
		if shouldCache(attr) {
			if r.Status.Allowed {
				w.responseCache.Add(string(key), r.Status, w.authorizedTTL)
			} else {
				w.responseCache.Add(string(key), r.Status, w.unauthorizedTTL)
			}
		}
	}
	switch {
	case r.Status.Denied && r.Status.Allowed:
		return authorizer.DecisionDeny, r.Status.Reason, fmt.Errorf("webhook subject access review returned both allow and deny response")
	case r.Status.Denied:
		return authorizer.DecisionDeny, r.Status.Reason, nil
	case r.Status.Allowed:
		return authorizer.DecisionAllow, r.Status.Reason, nil
	default:
		return authorizer.DecisionNoOpinion, r.Status.Reason, nil
	}

}

// TODO: need to finish the method to get the rules when using webhook mode
func (w *WebhookAuthorizer) RulesFor(user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	var (
		resourceRules    []authorizer.ResourceRuleInfo
		nonResourceRules []authorizer.NonResourceRuleInfo
	)
	incomplete := true
	return resourceRules, nonResourceRules, incomplete, fmt.Errorf("webhook authorizer does not support user rule resolution")
}

// Match is used to evaluate the request against the authorizer's cel expression to return match or no match found
func (w *WebhookAuthorizer) Match(ctx context.Context, r *authorizationv1.SubjectAccessReview) (bool, error) {
	if r.Spec.ResourceAttributes == nil {
		return false, nil
	}
	// if len(w.matchConditions) > 0 {
	// 	return false, nil
	// }
	expression := "request.name == 'my-pod'"
	env, err := cel.NewEnv()
	if err != nil {
		return false, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil {
		return false, fmt.Errorf("compilation failed: %s", issues.String())
	}
	if ast.OutputType() != cel.BoolType {
		return false, fmt.Errorf("cel expression must evaluate to a bool, instead got type: %s", ast.OutputType())
	}
	_, err = cel.AstToCheckedExpr(ast)
	if err != nil {
		if err != nil {
			return false, fmt.Errorf("unexpected compilation error: %v", err)
		}
	}
	prog, err := env.Program(ast,
		cel.InterruptCheckFrequency(celconfig.CheckFrequency),
	)
	if err != nil {
		// TODO: check failurePolicy
		return false, fmt.Errorf("program instantiation failed: " + err.Error())
	}
	
	requestVal, err := convertObjectToUnstructured(r.Spec.ResourceAttributes)
	if err != nil {
		return false, fmt.Errorf("convert object to unstructured failed: " + err.Error())
	}
	input := &evaluationActivation{
		request: requestVal.Object,
	}
	klog.Infof("cel input: %v", input)
	evalResult, evalDetails, err := prog.ContextEval(ctx, input)
	if err != nil {
		return false, fmt.Errorf("program eval failed: %v, evalDetails: %v", err, evalDetails)
	}
	klog.Infof("evalResult: %v", evalResult)
	klog.Infof("evalDetails: %v", evalDetails)
	if evalResult == celtypes.False {
		return false, nil
	}
	return true, nil
}

func convertObjectToUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	if obj == nil || reflect.ValueOf(obj).IsNil() {
		return &unstructured.Unstructured{Object: nil}, nil
	}
	ret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: ret}, nil
}

func convertToSARExtra(extra map[string][]string) map[string]authorizationv1.ExtraValue {
	if extra == nil {
		return nil
	}
	ret := map[string]authorizationv1.ExtraValue{}
	for k, v := range extra {
		ret[k] = authorizationv1.ExtraValue(v)
	}

	return ret
}

// subjectAccessReviewInterfaceFromConfig builds a client from the specified kubeconfig file,
// and returns a SubjectAccessReviewInterface that uses that client. Note that the client submits SubjectAccessReview
// requests to the exact path specified in the kubeconfig file, so arbitrary non-API servers can be targeted.
func subjectAccessReviewInterfaceFromConfig(config *rest.Config, version string, retryBackoff wait.Backoff) (subjectAccessReviewer, error) {
	localScheme := runtime.NewScheme()
	if err := scheme.AddToScheme(localScheme); err != nil {
		return nil, err
	}

	switch version {
	case authorizationv1.SchemeGroupVersion.Version:
		groupVersions := []schema.GroupVersion{authorizationv1.SchemeGroupVersion}
		if err := localScheme.SetVersionPriority(groupVersions...); err != nil {
			return nil, err
		}
		gw, err := webhook.NewGenericWebhook(localScheme, scheme.Codecs, config, groupVersions, retryBackoff)
		if err != nil {
			return nil, err
		}
		return &subjectAccessReviewV1ClientGW{gw.RestClient}, nil

	case authorizationv1beta1.SchemeGroupVersion.Version:
		groupVersions := []schema.GroupVersion{authorizationv1beta1.SchemeGroupVersion}
		if err := localScheme.SetVersionPriority(groupVersions...); err != nil {
			return nil, err
		}
		gw, err := webhook.NewGenericWebhook(localScheme, scheme.Codecs, config, groupVersions, retryBackoff)
		if err != nil {
			return nil, err
		}
		return &subjectAccessReviewV1beta1ClientGW{gw.RestClient}, nil

	default:
		return nil, fmt.Errorf(
			"unsupported webhook authorizer version %q, supported versions are %q, %q",
			version,
			authorizationv1.SchemeGroupVersion.Version,
			authorizationv1beta1.SchemeGroupVersion.Version,
		)
	}
}

type subjectAccessReviewV1Client struct {
	client rest.Interface
}

func (t *subjectAccessReviewV1Client) Create(ctx context.Context, subjectAccessReview *authorizationv1.SubjectAccessReview, opts metav1.CreateOptions) (result *authorizationv1.SubjectAccessReview, statusCode int, err error) {
	result = &authorizationv1.SubjectAccessReview{}

	restResult := t.client.Post().
		Resource("subjectaccessreviews").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(subjectAccessReview).
		Do(ctx)

	restResult.StatusCode(&statusCode)
	err = restResult.Into(result)
	return
}

// subjectAccessReviewV1ClientGW used by the generic webhook, doesn't specify GVR.
type subjectAccessReviewV1ClientGW struct {
	client rest.Interface
}

func (t *subjectAccessReviewV1ClientGW) Create(ctx context.Context, subjectAccessReview *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, int, error) {
	var statusCode int
	result := &authorizationv1.SubjectAccessReview{}

	restResult := t.client.Post().Body(subjectAccessReview).Do(ctx)

	restResult.StatusCode(&statusCode)
	err := restResult.Into(result)

	return result, statusCode, err
}

// subjectAccessReviewV1beta1ClientGW used by the generic webhook, doesn't specify GVR.
type subjectAccessReviewV1beta1ClientGW struct {
	client rest.Interface
}

func (t *subjectAccessReviewV1beta1ClientGW) Create(ctx context.Context, subjectAccessReview *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, int, error) {
	var statusCode int
	v1beta1Review := &authorizationv1beta1.SubjectAccessReview{Spec: v1SpecToV1beta1Spec(&subjectAccessReview.Spec)}
	v1beta1Result := &authorizationv1beta1.SubjectAccessReview{}

	restResult := t.client.Post().Body(v1beta1Review).Do(ctx)

	restResult.StatusCode(&statusCode)
	err := restResult.Into(v1beta1Result)
	if err == nil {
		subjectAccessReview.Status = v1beta1StatusToV1Status(&v1beta1Result.Status)
	}
	return subjectAccessReview, statusCode, err
}

// shouldCache determines whether it is safe to cache the given request attributes. If the
// requester-controlled attributes are too large, this may be a DoS attempt, so we skip the cache.
func shouldCache(attr authorizer.Attributes) bool {
	controlledAttrSize := int64(len(attr.GetNamespace())) +
		int64(len(attr.GetVerb())) +
		int64(len(attr.GetAPIGroup())) +
		int64(len(attr.GetAPIVersion())) +
		int64(len(attr.GetResource())) +
		int64(len(attr.GetSubresource())) +
		int64(len(attr.GetName())) +
		int64(len(attr.GetPath()))
	return controlledAttrSize < maxControlledAttrCacheSize
}

func v1beta1StatusToV1Status(in *authorizationv1beta1.SubjectAccessReviewStatus) authorizationv1.SubjectAccessReviewStatus {
	return authorizationv1.SubjectAccessReviewStatus{
		Allowed:         in.Allowed,
		Denied:          in.Denied,
		Reason:          in.Reason,
		EvaluationError: in.EvaluationError,
	}
}

func v1SpecToV1beta1Spec(in *authorizationv1.SubjectAccessReviewSpec) authorizationv1beta1.SubjectAccessReviewSpec {
	return authorizationv1beta1.SubjectAccessReviewSpec{
		ResourceAttributes:    v1ResourceAttributesToV1beta1ResourceAttributes(in.ResourceAttributes),
		NonResourceAttributes: v1NonResourceAttributesToV1beta1NonResourceAttributes(in.NonResourceAttributes),
		User:                  in.User,
		Groups:                in.Groups,
		Extra:                 v1ExtraToV1beta1Extra(in.Extra),
		UID:                   in.UID,
	}
}

func v1ResourceAttributesToV1beta1ResourceAttributes(in *authorizationv1.ResourceAttributes) *authorizationv1beta1.ResourceAttributes {
	if in == nil {
		return nil
	}
	return &authorizationv1beta1.ResourceAttributes{
		Namespace:   in.Namespace,
		Verb:        in.Verb,
		Group:       in.Group,
		Version:     in.Version,
		Resource:    in.Resource,
		Subresource: in.Subresource,
		Name:        in.Name,
	}
}

func v1NonResourceAttributesToV1beta1NonResourceAttributes(in *authorizationv1.NonResourceAttributes) *authorizationv1beta1.NonResourceAttributes {
	if in == nil {
		return nil
	}
	return &authorizationv1beta1.NonResourceAttributes{
		Path: in.Path,
		Verb: in.Verb,
	}
}

func v1ExtraToV1beta1Extra(in map[string]authorizationv1.ExtraValue) map[string]authorizationv1beta1.ExtraValue {
	if in == nil {
		return nil
	}
	ret := make(map[string]authorizationv1beta1.ExtraValue, len(in))
	for k, v := range in {
		ret[k] = authorizationv1beta1.ExtraValue(v)
	}
	return ret
}
