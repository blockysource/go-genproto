// Copyright 2023 The Blocky Authors
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: blocky/authz/admin/v1alpha/client_admin.proto

package authzadminv1alpha

import (
	_ "github.com/blockysource/go-genproto/blocky/api/annotations"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The request message for
// [ClientAdminService.ListClient][blocky.authz.admin.v1alpha.ClientAdminService.ListClient].
type CreateClientRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The parent instance where the client will be created.
	Parent string `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	// User specified unique client identifier.
	// The client id must be 1 to 63 characters long and contain only
	// lowercase letters, numeric characters, and dashes.
	// The id should only be a 'clientid' and not a full resource path:
	// "projects/*/clients/{clientid}".
	// If not specified by the caller, the server will generate a random.
	ClientId string `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	// Client is a authorization client used to authorize requests.
	Client *Client `protobuf:"bytes,3,opt,name=client,proto3" json:"client,omitempty"`
}

func (x *CreateClientRequest) Reset() {
	*x = CreateClientRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateClientRequest) ProtoMessage() {}

func (x *CreateClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateClientRequest.ProtoReflect.Descriptor instead.
func (*CreateClientRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{0}
}

func (x *CreateClientRequest) GetParent() string {
	if x != nil {
		return x.Parent
	}
	return ""
}

func (x *CreateClientRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *CreateClientRequest) GetClient() *Client {
	if x != nil {
		return x.Client
	}
	return nil
}

// The request message for
// [ClientAdminService.ListClient][blocky.authz.admin.v1alpha.ClientAdminService.ListClient].
type ListClientRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The parent instance whose clients are listed.
	Parent string `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	// The maximum number of clients to return.
	// The service may return fewer than this value.
	// If unspecified, at most 20 clients will be returned.
	PageSize int32 `protobuf:"varint,2,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// A page token, received from a previous
	// [ClientAdminService.ListClient][blocky.authz.admin.v1alpha.ClientAdminService.ListClient] call.
	// Provide this to retrieve the subsequent page.
	PageToken string `protobuf:"bytes,3,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *ListClientRequest) Reset() {
	*x = ListClientRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListClientRequest) ProtoMessage() {}

func (x *ListClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListClientRequest.ProtoReflect.Descriptor instead.
func (*ListClientRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{1}
}

func (x *ListClientRequest) GetParent() string {
	if x != nil {
		return x.Parent
	}
	return ""
}

func (x *ListClientRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *ListClientRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

// The response message for
// [ClientAdminService.ListClient][blocky.authz.admin.v1alpha.ClientAdminService.ListClient].
type ListClientResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The list of clients.
	Clients []*Client `protobuf:"bytes,1,rep,name=clients,proto3" json:"clients,omitempty"`
	// A token to retrieve the next page of results.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *ListClientResponse) Reset() {
	*x = ListClientResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListClientResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListClientResponse) ProtoMessage() {}

func (x *ListClientResponse) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListClientResponse.ProtoReflect.Descriptor instead.
func (*ListClientResponse) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{2}
}

func (x *ListClientResponse) GetClients() []*Client {
	if x != nil {
		return x.Clients
	}
	return nil
}

func (x *ListClientResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

// The request message for
// [ClientAdminService.GetClient][blocky.authz.admin.v1alpha.ClientAdminService.GetClient].
type GetClientRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required. The name of the client to retrieve.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetClientRequest) Reset() {
	*x = GetClientRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetClientRequest) ProtoMessage() {}

func (x *GetClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetClientRequest.ProtoReflect.Descriptor instead.
func (*GetClientRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{3}
}

func (x *GetClientRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// The request message for
// [ClientAdminService.DeleteClient][blocky.authz.admin.v1alpha.ClientAdminService.DeleteClient].
type DeleteClientRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the client to delete.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteClientRequest) Reset() {
	*x = DeleteClientRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteClientRequest) ProtoMessage() {}

func (x *DeleteClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteClientRequest.ProtoReflect.Descriptor instead.
func (*DeleteClientRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{4}
}

func (x *DeleteClientRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// The request message for
// [ClientAdminService.UpdateClient][blocky.authz.admin.v1alpha.ClientAdminService.UpdateClient].
type UpdateClientRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The client to update.
	Client *Client `protobuf:"bytes,1,opt,name=client,proto3" json:"client,omitempty"`
}

func (x *UpdateClientRequest) Reset() {
	*x = UpdateClientRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateClientRequest) ProtoMessage() {}

func (x *UpdateClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateClientRequest.ProtoReflect.Descriptor instead.
func (*UpdateClientRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{5}
}

func (x *UpdateClientRequest) GetClient() *Client {
	if x != nil {
		return x.Client
	}
	return nil
}

// The request message for
// [ClientAdminService.ShowCredentials][blocky.authz.admin.v1alpha.ClientAdminService.ShowCredentials].
type ShowClientCredentialsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required. The name of the client to retrieve credentials for.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *ShowClientCredentialsRequest) Reset() {
	*x = ShowClientCredentialsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShowClientCredentialsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShowClientCredentialsRequest) ProtoMessage() {}

func (x *ShowClientCredentialsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShowClientCredentialsRequest.ProtoReflect.Descriptor instead.
func (*ShowClientCredentialsRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP(), []int{6}
}

func (x *ShowClientCredentialsRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_blocky_authz_admin_v1alpha_client_admin_proto protoreflect.FileDescriptor

var file_blocky_authz_admin_v1alpha_client_admin_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x1a, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64,
	0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1c, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x17, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61,
	0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xc5, 0x01, 0x0a, 0x13, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x4b, 0x0a, 0x06, 0x70, 0x61,
	0x72, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x33, 0xe0, 0x41, 0x02, 0xfa,
	0x41, 0x2d, 0x0a, 0x2b, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61,
	0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x52,
	0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x12, 0x20, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52,
	0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x3f, 0x0a, 0x06, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x42, 0x03, 0xe0,
	0x41, 0x02, 0x52, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x22, 0xa6, 0x01, 0x0a, 0x11, 0x4c,
	0x69, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x4b, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x33, 0xe0, 0x41, 0x02, 0xfa, 0x41, 0x2d, 0x0a, 0x2b, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x50, 0x72,
	0x6f, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x12, 0x20, 0x0a,
	0x09, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05,
	0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12,
	0x22, 0x0a, 0x0a, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x09, 0x70, 0x61, 0x67, 0x65, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x22, 0x7a, 0x0a, 0x12, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3c, 0x0a, 0x07, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x07,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f,
	0x70, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x50, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22,
	0x2b, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x4e, 0x0a, 0x13,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x37, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x23, 0xe0, 0x41, 0x02, 0xfa, 0x41, 0x1d, 0x0a, 0x1b, 0x61, 0x75, 0x74, 0x68, 0x7a,
	0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x56, 0x0a, 0x13,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x3f, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74,
	0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x22, 0x57, 0x0a, 0x1c, 0x53, 0x68, 0x6f, 0x77, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x37, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x23, 0xe0, 0x41, 0x02, 0xfa, 0x41, 0x1d, 0x0a, 0x1b, 0x61, 0x75, 0x74, 0x68,
	0x7a, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x32, 0xc1, 0x08,
	0x0a, 0x12, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x12, 0xa4, 0x01, 0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x2f, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e,
	0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x22, 0x3f, 0xda, 0x41, 0x0d, 0x70,
	0x61, 0x72, 0x65, 0x6e, 0x74, 0x2c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x29, 0x3a, 0x01, 0x2a, 0x22, 0x24, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f,
	0x7b, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x3d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73,
	0x2f, 0x2a, 0x7d, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x12, 0xbf, 0x01, 0x0a, 0x0a,
	0x4c, 0x69, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x2d, 0x2e, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2e, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x52, 0xda, 0x41, 0x06, 0x70, 0x61,
	0x72, 0x65, 0x6e, 0x74, 0xa2, 0xec, 0xd7, 0x4d, 0x18, 0x0a, 0x04, 0x08, 0x64, 0x10, 0x14, 0x12,
	0x10, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x64, 0x65, 0x73,
	0x63, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x26, 0x12, 0x24, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2f, 0x7b, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x3d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63,
	0x74, 0x73, 0x2f, 0x2a, 0x7d, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x92, 0x01,
	0x0a, 0x09, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x2c, 0x2e, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x22, 0x33, 0xda,
	0x41, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x26, 0x12, 0x24, 0x2f, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x7b, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x70, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x2a, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x2f,
	0x2a, 0x7d, 0x12, 0xa9, 0x01, 0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x12, 0x2f, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74,
	0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75,
	0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x22, 0x44, 0xda, 0x41, 0x06, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x35, 0x3a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x32, 0x2b, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x7b, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x2e, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
	0x73, 0x2f, 0x2a, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x2a, 0x7d, 0x12, 0x8c,
	0x01, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12,
	0x2f, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x44, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x33, 0xda, 0x41, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x26, 0x2a, 0x24, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2f, 0x7b, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73,
	0x2f, 0x2a, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x2a, 0x7d, 0x12, 0xc1, 0x01,
	0x0a, 0x15, 0x53, 0x68, 0x6f, 0x77, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x38, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2e, 0x53, 0x68, 0x6f, 0x77, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x2d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a,
	0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x22, 0x3f, 0xda, 0x41, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x32, 0x12,
	0x30, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x7b, 0x6e, 0x61, 0x6d, 0x65, 0x3d,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x2a, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x2f, 0x2a, 0x7d, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x1a, 0x2e, 0xd2, 0x41, 0x2b, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
	0x77, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69,
	0x6e, 0x42, 0x8f, 0x02, 0x0a, 0x1e, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x42, 0x10, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x6d, 0x69,
	0x6e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x50, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e,
	0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x61, 0x64,
	0x6d, 0x69, 0x6e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xa2, 0x02, 0x03, 0x42, 0x41, 0x41,
	0xaa, 0x02, 0x1a, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x2e,
	0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca, 0x02, 0x1a,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x41, 0x64, 0x6d,
	0x69, 0x6e, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xe2, 0x02, 0x26, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x5c,
	0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0xea, 0x02, 0x1d, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x41, 0x75,
	0x74, 0x68, 0x7a, 0x3a, 0x3a, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x3a, 0x3a, 0x56, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescOnce sync.Once
	file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescData = file_blocky_authz_admin_v1alpha_client_admin_proto_rawDesc
)

func file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescGZIP() []byte {
	file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescOnce.Do(func() {
		file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescData)
	})
	return file_blocky_authz_admin_v1alpha_client_admin_proto_rawDescData
}

var file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_blocky_authz_admin_v1alpha_client_admin_proto_goTypes = []interface{}{
	(*CreateClientRequest)(nil),          // 0: blocky.authz.admin.v1alpha.CreateClientRequest
	(*ListClientRequest)(nil),            // 1: blocky.authz.admin.v1alpha.ListClientRequest
	(*ListClientResponse)(nil),           // 2: blocky.authz.admin.v1alpha.ListClientResponse
	(*GetClientRequest)(nil),             // 3: blocky.authz.admin.v1alpha.GetClientRequest
	(*DeleteClientRequest)(nil),          // 4: blocky.authz.admin.v1alpha.DeleteClientRequest
	(*UpdateClientRequest)(nil),          // 5: blocky.authz.admin.v1alpha.UpdateClientRequest
	(*ShowClientCredentialsRequest)(nil), // 6: blocky.authz.admin.v1alpha.ShowClientCredentialsRequest
	(*Client)(nil),                       // 7: blocky.authz.admin.v1alpha.Client
	(*emptypb.Empty)(nil),                // 8: google.protobuf.Empty
	(*ClientCredentials)(nil),            // 9: blocky.authz.admin.v1alpha.ClientCredentials
}
var file_blocky_authz_admin_v1alpha_client_admin_proto_depIdxs = []int32{
	7, // 0: blocky.authz.admin.v1alpha.CreateClientRequest.client:type_name -> blocky.authz.admin.v1alpha.Client
	7, // 1: blocky.authz.admin.v1alpha.ListClientResponse.clients:type_name -> blocky.authz.admin.v1alpha.Client
	7, // 2: blocky.authz.admin.v1alpha.UpdateClientRequest.client:type_name -> blocky.authz.admin.v1alpha.Client
	0, // 3: blocky.authz.admin.v1alpha.ClientAdminService.CreateClient:input_type -> blocky.authz.admin.v1alpha.CreateClientRequest
	1, // 4: blocky.authz.admin.v1alpha.ClientAdminService.ListClient:input_type -> blocky.authz.admin.v1alpha.ListClientRequest
	3, // 5: blocky.authz.admin.v1alpha.ClientAdminService.GetClient:input_type -> blocky.authz.admin.v1alpha.GetClientRequest
	5, // 6: blocky.authz.admin.v1alpha.ClientAdminService.UpdateClient:input_type -> blocky.authz.admin.v1alpha.UpdateClientRequest
	4, // 7: blocky.authz.admin.v1alpha.ClientAdminService.DeleteClient:input_type -> blocky.authz.admin.v1alpha.DeleteClientRequest
	6, // 8: blocky.authz.admin.v1alpha.ClientAdminService.ShowClientCredentials:input_type -> blocky.authz.admin.v1alpha.ShowClientCredentialsRequest
	7, // 9: blocky.authz.admin.v1alpha.ClientAdminService.CreateClient:output_type -> blocky.authz.admin.v1alpha.Client
	2, // 10: blocky.authz.admin.v1alpha.ClientAdminService.ListClient:output_type -> blocky.authz.admin.v1alpha.ListClientResponse
	7, // 11: blocky.authz.admin.v1alpha.ClientAdminService.GetClient:output_type -> blocky.authz.admin.v1alpha.Client
	7, // 12: blocky.authz.admin.v1alpha.ClientAdminService.UpdateClient:output_type -> blocky.authz.admin.v1alpha.Client
	8, // 13: blocky.authz.admin.v1alpha.ClientAdminService.DeleteClient:output_type -> google.protobuf.Empty
	9, // 14: blocky.authz.admin.v1alpha.ClientAdminService.ShowClientCredentials:output_type -> blocky.authz.admin.v1alpha.ClientCredentials
	9, // [9:15] is the sub-list for method output_type
	3, // [3:9] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_blocky_authz_admin_v1alpha_client_admin_proto_init() }
func file_blocky_authz_admin_v1alpha_client_admin_proto_init() {
	if File_blocky_authz_admin_v1alpha_client_admin_proto != nil {
		return
	}
	file_blocky_authz_admin_v1alpha_client_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateClientRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListClientRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListClientResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetClientRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteClientRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateClientRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShowClientCredentialsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_blocky_authz_admin_v1alpha_client_admin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_blocky_authz_admin_v1alpha_client_admin_proto_goTypes,
		DependencyIndexes: file_blocky_authz_admin_v1alpha_client_admin_proto_depIdxs,
		MessageInfos:      file_blocky_authz_admin_v1alpha_client_admin_proto_msgTypes,
	}.Build()
	File_blocky_authz_admin_v1alpha_client_admin_proto = out.File
	file_blocky_authz_admin_v1alpha_client_admin_proto_rawDesc = nil
	file_blocky_authz_admin_v1alpha_client_admin_proto_goTypes = nil
	file_blocky_authz_admin_v1alpha_client_admin_proto_depIdxs = nil
}
