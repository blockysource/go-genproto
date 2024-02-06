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
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// New creates a new event message.
func New(sourceService string, msg proto.Message, metadata map[string]any) (*Message, error) {
	// Generate identifier.
	id, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}

	// Marshal the payload yo the protobuf anypb.Any implementation.
	payload, err := anypb.New(msg)
	if err != nil {
		return nil, err
	}

	// Define the message structure.
	e := Message{
		EventId:       id.String(),
		Timestamp:     timestamppb.Now(),
		SourceService: sourceService,
		Payload:       payload,
	}

	// If metadata provided create a new structpb.Struct and assign from input metadata.
	if metadata != nil {
		e.Metadata, err = structpb.NewStruct(metadata)
		if err != nil {
			return nil, err
		}
	}
	return &e, nil
}
