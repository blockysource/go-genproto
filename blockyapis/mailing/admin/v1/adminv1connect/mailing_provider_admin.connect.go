// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: blockyapis/mailing/admin/v1/mailing_provider_admin.proto

package adminv1connect

import (
	context "context"
	errors "errors"
	v1 "github.com/blockysource/go-genproto/blockyapis/mailing/admin/v1"
	connect_go "github.com/bufbuild/connect-go"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect_go.IsAtLeastVersion0_1_0

const (
	// MailingProviderAdminName is the fully-qualified name of the MailingProviderAdmin service.
	MailingProviderAdminName = "blockyapis.mailing.admin.v1.MailingProviderAdmin"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// MailingProviderAdminCreateMailingProviderProcedure is the fully-qualified name of the
	// MailingProviderAdmin's CreateMailingProvider RPC.
	MailingProviderAdminCreateMailingProviderProcedure = "/blockyapis.mailing.admin.v1.MailingProviderAdmin/CreateMailingProvider"
	// MailingProviderAdminSetCurrentMailingProviderProcedure is the fully-qualified name of the
	// MailingProviderAdmin's SetCurrentMailingProvider RPC.
	MailingProviderAdminSetCurrentMailingProviderProcedure = "/blockyapis.mailing.admin.v1.MailingProviderAdmin/SetCurrentMailingProvider"
	// MailingProviderAdminUpdateMailingProviderProcedure is the fully-qualified name of the
	// MailingProviderAdmin's UpdateMailingProvider RPC.
	MailingProviderAdminUpdateMailingProviderProcedure = "/blockyapis.mailing.admin.v1.MailingProviderAdmin/UpdateMailingProvider"
	// MailingProviderAdminListMailingProvidersProcedure is the fully-qualified name of the
	// MailingProviderAdmin's ListMailingProviders RPC.
	MailingProviderAdminListMailingProvidersProcedure = "/blockyapis.mailing.admin.v1.MailingProviderAdmin/ListMailingProviders"
	// MailingProviderAdminGetCurrentMailingProviderProcedure is the fully-qualified name of the
	// MailingProviderAdmin's GetCurrentMailingProvider RPC.
	MailingProviderAdminGetCurrentMailingProviderProcedure = "/blockyapis.mailing.admin.v1.MailingProviderAdmin/GetCurrentMailingProvider"
)

// MailingProviderAdminClient is a client for the blockyapis.mailing.admin.v1.MailingProviderAdmin
// service.
type MailingProviderAdminClient interface {
	CreateMailingProvider(context.Context, *connect_go.Request[v1.CreateMailingProviderRequest]) (*connect_go.Response[v1.CreateMailingProviderResponse], error)
	SetCurrentMailingProvider(context.Context, *connect_go.Request[v1.SetCurrentMailingProviderRequest]) (*connect_go.Response[v1.SetCurrentMailingProviderResponse], error)
	UpdateMailingProvider(context.Context, *connect_go.Request[v1.UpdateMailingProviderRequest]) (*connect_go.Response[v1.UpdateMailingProviderResponse], error)
	ListMailingProviders(context.Context, *connect_go.Request[v1.ListMailingProvidersRequest]) (*connect_go.Response[v1.ListMailingProvidersResponse], error)
	GetCurrentMailingProvider(context.Context, *connect_go.Request[v1.GetCurrentMailingProviderRequest]) (*connect_go.Response[v1.GetCurrentMailingProviderResponse], error)
}

// NewMailingProviderAdminClient constructs a client for the
// blockyapis.mailing.admin.v1.MailingProviderAdmin service. By default, it uses the Connect
// protocol with the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed
// requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or
// connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewMailingProviderAdminClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) MailingProviderAdminClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &mailingProviderAdminClient{
		createMailingProvider: connect_go.NewClient[v1.CreateMailingProviderRequest, v1.CreateMailingProviderResponse](
			httpClient,
			baseURL+MailingProviderAdminCreateMailingProviderProcedure,
			opts...,
		),
		setCurrentMailingProvider: connect_go.NewClient[v1.SetCurrentMailingProviderRequest, v1.SetCurrentMailingProviderResponse](
			httpClient,
			baseURL+MailingProviderAdminSetCurrentMailingProviderProcedure,
			opts...,
		),
		updateMailingProvider: connect_go.NewClient[v1.UpdateMailingProviderRequest, v1.UpdateMailingProviderResponse](
			httpClient,
			baseURL+MailingProviderAdminUpdateMailingProviderProcedure,
			opts...,
		),
		listMailingProviders: connect_go.NewClient[v1.ListMailingProvidersRequest, v1.ListMailingProvidersResponse](
			httpClient,
			baseURL+MailingProviderAdminListMailingProvidersProcedure,
			opts...,
		),
		getCurrentMailingProvider: connect_go.NewClient[v1.GetCurrentMailingProviderRequest, v1.GetCurrentMailingProviderResponse](
			httpClient,
			baseURL+MailingProviderAdminGetCurrentMailingProviderProcedure,
			opts...,
		),
	}
}

// mailingProviderAdminClient implements MailingProviderAdminClient.
type mailingProviderAdminClient struct {
	createMailingProvider     *connect_go.Client[v1.CreateMailingProviderRequest, v1.CreateMailingProviderResponse]
	setCurrentMailingProvider *connect_go.Client[v1.SetCurrentMailingProviderRequest, v1.SetCurrentMailingProviderResponse]
	updateMailingProvider     *connect_go.Client[v1.UpdateMailingProviderRequest, v1.UpdateMailingProviderResponse]
	listMailingProviders      *connect_go.Client[v1.ListMailingProvidersRequest, v1.ListMailingProvidersResponse]
	getCurrentMailingProvider *connect_go.Client[v1.GetCurrentMailingProviderRequest, v1.GetCurrentMailingProviderResponse]
}

// CreateMailingProvider calls
// blockyapis.mailing.admin.v1.MailingProviderAdmin.CreateMailingProvider.
func (c *mailingProviderAdminClient) CreateMailingProvider(ctx context.Context, req *connect_go.Request[v1.CreateMailingProviderRequest]) (*connect_go.Response[v1.CreateMailingProviderResponse], error) {
	return c.createMailingProvider.CallUnary(ctx, req)
}

// SetCurrentMailingProvider calls
// blockyapis.mailing.admin.v1.MailingProviderAdmin.SetCurrentMailingProvider.
func (c *mailingProviderAdminClient) SetCurrentMailingProvider(ctx context.Context, req *connect_go.Request[v1.SetCurrentMailingProviderRequest]) (*connect_go.Response[v1.SetCurrentMailingProviderResponse], error) {
	return c.setCurrentMailingProvider.CallUnary(ctx, req)
}

// UpdateMailingProvider calls
// blockyapis.mailing.admin.v1.MailingProviderAdmin.UpdateMailingProvider.
func (c *mailingProviderAdminClient) UpdateMailingProvider(ctx context.Context, req *connect_go.Request[v1.UpdateMailingProviderRequest]) (*connect_go.Response[v1.UpdateMailingProviderResponse], error) {
	return c.updateMailingProvider.CallUnary(ctx, req)
}

// ListMailingProviders calls blockyapis.mailing.admin.v1.MailingProviderAdmin.ListMailingProviders.
func (c *mailingProviderAdminClient) ListMailingProviders(ctx context.Context, req *connect_go.Request[v1.ListMailingProvidersRequest]) (*connect_go.Response[v1.ListMailingProvidersResponse], error) {
	return c.listMailingProviders.CallUnary(ctx, req)
}

// GetCurrentMailingProvider calls
// blockyapis.mailing.admin.v1.MailingProviderAdmin.GetCurrentMailingProvider.
func (c *mailingProviderAdminClient) GetCurrentMailingProvider(ctx context.Context, req *connect_go.Request[v1.GetCurrentMailingProviderRequest]) (*connect_go.Response[v1.GetCurrentMailingProviderResponse], error) {
	return c.getCurrentMailingProvider.CallUnary(ctx, req)
}

// MailingProviderAdminHandler is an implementation of the
// blockyapis.mailing.admin.v1.MailingProviderAdmin service.
type MailingProviderAdminHandler interface {
	CreateMailingProvider(context.Context, *connect_go.Request[v1.CreateMailingProviderRequest]) (*connect_go.Response[v1.CreateMailingProviderResponse], error)
	SetCurrentMailingProvider(context.Context, *connect_go.Request[v1.SetCurrentMailingProviderRequest]) (*connect_go.Response[v1.SetCurrentMailingProviderResponse], error)
	UpdateMailingProvider(context.Context, *connect_go.Request[v1.UpdateMailingProviderRequest]) (*connect_go.Response[v1.UpdateMailingProviderResponse], error)
	ListMailingProviders(context.Context, *connect_go.Request[v1.ListMailingProvidersRequest]) (*connect_go.Response[v1.ListMailingProvidersResponse], error)
	GetCurrentMailingProvider(context.Context, *connect_go.Request[v1.GetCurrentMailingProviderRequest]) (*connect_go.Response[v1.GetCurrentMailingProviderResponse], error)
}

// NewMailingProviderAdminHandler builds an HTTP handler from the service implementation. It returns
// the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewMailingProviderAdminHandler(svc MailingProviderAdminHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	mailingProviderAdminCreateMailingProviderHandler := connect_go.NewUnaryHandler(
		MailingProviderAdminCreateMailingProviderProcedure,
		svc.CreateMailingProvider,
		opts...,
	)
	mailingProviderAdminSetCurrentMailingProviderHandler := connect_go.NewUnaryHandler(
		MailingProviderAdminSetCurrentMailingProviderProcedure,
		svc.SetCurrentMailingProvider,
		opts...,
	)
	mailingProviderAdminUpdateMailingProviderHandler := connect_go.NewUnaryHandler(
		MailingProviderAdminUpdateMailingProviderProcedure,
		svc.UpdateMailingProvider,
		opts...,
	)
	mailingProviderAdminListMailingProvidersHandler := connect_go.NewUnaryHandler(
		MailingProviderAdminListMailingProvidersProcedure,
		svc.ListMailingProviders,
		opts...,
	)
	mailingProviderAdminGetCurrentMailingProviderHandler := connect_go.NewUnaryHandler(
		MailingProviderAdminGetCurrentMailingProviderProcedure,
		svc.GetCurrentMailingProvider,
		opts...,
	)
	return "/blockyapis.mailing.admin.v1.MailingProviderAdmin/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case MailingProviderAdminCreateMailingProviderProcedure:
			mailingProviderAdminCreateMailingProviderHandler.ServeHTTP(w, r)
		case MailingProviderAdminSetCurrentMailingProviderProcedure:
			mailingProviderAdminSetCurrentMailingProviderHandler.ServeHTTP(w, r)
		case MailingProviderAdminUpdateMailingProviderProcedure:
			mailingProviderAdminUpdateMailingProviderHandler.ServeHTTP(w, r)
		case MailingProviderAdminListMailingProvidersProcedure:
			mailingProviderAdminListMailingProvidersHandler.ServeHTTP(w, r)
		case MailingProviderAdminGetCurrentMailingProviderProcedure:
			mailingProviderAdminGetCurrentMailingProviderHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedMailingProviderAdminHandler returns CodeUnimplemented from all methods.
type UnimplementedMailingProviderAdminHandler struct{}

func (UnimplementedMailingProviderAdminHandler) CreateMailingProvider(context.Context, *connect_go.Request[v1.CreateMailingProviderRequest]) (*connect_go.Response[v1.CreateMailingProviderResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blockyapis.mailing.admin.v1.MailingProviderAdmin.CreateMailingProvider is not implemented"))
}

func (UnimplementedMailingProviderAdminHandler) SetCurrentMailingProvider(context.Context, *connect_go.Request[v1.SetCurrentMailingProviderRequest]) (*connect_go.Response[v1.SetCurrentMailingProviderResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blockyapis.mailing.admin.v1.MailingProviderAdmin.SetCurrentMailingProvider is not implemented"))
}

func (UnimplementedMailingProviderAdminHandler) UpdateMailingProvider(context.Context, *connect_go.Request[v1.UpdateMailingProviderRequest]) (*connect_go.Response[v1.UpdateMailingProviderResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blockyapis.mailing.admin.v1.MailingProviderAdmin.UpdateMailingProvider is not implemented"))
}

func (UnimplementedMailingProviderAdminHandler) ListMailingProviders(context.Context, *connect_go.Request[v1.ListMailingProvidersRequest]) (*connect_go.Response[v1.ListMailingProvidersResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blockyapis.mailing.admin.v1.MailingProviderAdmin.ListMailingProviders is not implemented"))
}

func (UnimplementedMailingProviderAdminHandler) GetCurrentMailingProvider(context.Context, *connect_go.Request[v1.GetCurrentMailingProviderRequest]) (*connect_go.Response[v1.GetCurrentMailingProviderResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blockyapis.mailing.admin.v1.MailingProviderAdmin.GetCurrentMailingProvider is not implemented"))
}
