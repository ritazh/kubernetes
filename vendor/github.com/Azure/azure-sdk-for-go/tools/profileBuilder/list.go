package main

// Copyright 2017 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

import (
	"fmt"
	"io"

	"github.com/marstr/collection"
)

// ListStrategy allows a mechanism for a list of packages that should be included in a profile.
type ListStrategy struct {
	io.ReadSeeker
}

// Enumerate reads a new line delimited list of packages names relative to $GOPATH
func (list ListStrategy) Enumerate(cancel <-chan struct{}) collection.Enumerator {
	results := make(chan interface{})

	go func() {
		defer close(results)

		for {
			select {
			case _ = <-cancel:
			default:
				//Not cancelled
			}

			var line string
			var n int
			n, err := fmt.Fscanln(list, &line)
			if n == 0 || err != nil {
				fmt.Println(err)
				break
			}

			results <- line
		}
		list.Seek(0, 0)
	}()
	return results
}
