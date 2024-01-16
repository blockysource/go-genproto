// Copyright 2024 The Blocky Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eventpb

import (
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// New creates a new event message.
func New(sourceService, organization string, msg proto.Message) (*Message, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	payload, err := anypb.New(msg)
	if err != nil {
		return nil, err
	}
	e := Message{
		EventId:       id.String(),
		Timestamp:     timestamppb.Now(),
		SourceService: sourceService,
		Organization:  organization,
		Payload:       payload,
	}
	return &e, nil
}
