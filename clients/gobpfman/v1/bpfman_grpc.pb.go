// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.6
// source: bpfman.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// BpfmanClient is the client API for Bpfman service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BpfmanClient interface {
	Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*LoadResponse, error)
	Unload(ctx context.Context, in *UnloadRequest, opts ...grpc.CallOption) (*UnloadResponse, error)
	Attach(ctx context.Context, in *AttachRequest, opts ...grpc.CallOption) (*AttachResponse, error)
	List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error)
	PullBytecode(ctx context.Context, in *PullBytecodeRequest, opts ...grpc.CallOption) (*PullBytecodeResponse, error)
	Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error)
}

type bpfmanClient struct {
	cc grpc.ClientConnInterface
}

func NewBpfmanClient(cc grpc.ClientConnInterface) BpfmanClient {
	return &bpfmanClient{cc}
}

func (c *bpfmanClient) Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*LoadResponse, error) {
	out := new(LoadResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/Load", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bpfmanClient) Unload(ctx context.Context, in *UnloadRequest, opts ...grpc.CallOption) (*UnloadResponse, error) {
	out := new(UnloadResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/Unload", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bpfmanClient) Attach(ctx context.Context, in *AttachRequest, opts ...grpc.CallOption) (*AttachResponse, error) {
	out := new(AttachResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/Attach", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bpfmanClient) List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bpfmanClient) PullBytecode(ctx context.Context, in *PullBytecodeRequest, opts ...grpc.CallOption) (*PullBytecodeResponse, error) {
	out := new(PullBytecodeResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/PullBytecode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bpfmanClient) Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error) {
	out := new(GetResponse)
	err := c.cc.Invoke(ctx, "/bpfman.v1.Bpfman/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BpfmanServer is the server API for Bpfman service.
// All implementations must embed UnimplementedBpfmanServer
// for forward compatibility
type BpfmanServer interface {
	Load(context.Context, *LoadRequest) (*LoadResponse, error)
	Unload(context.Context, *UnloadRequest) (*UnloadResponse, error)
	Attach(context.Context, *AttachRequest) (*AttachResponse, error)
	List(context.Context, *ListRequest) (*ListResponse, error)
	PullBytecode(context.Context, *PullBytecodeRequest) (*PullBytecodeResponse, error)
	Get(context.Context, *GetRequest) (*GetResponse, error)
	mustEmbedUnimplementedBpfmanServer()
}

// UnimplementedBpfmanServer must be embedded to have forward compatible implementations.
type UnimplementedBpfmanServer struct {
}

func (UnimplementedBpfmanServer) Load(context.Context, *LoadRequest) (*LoadResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Load not implemented")
}
func (UnimplementedBpfmanServer) Unload(context.Context, *UnloadRequest) (*UnloadResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Unload not implemented")
}
func (UnimplementedBpfmanServer) Attach(context.Context, *AttachRequest) (*AttachResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Attach not implemented")
}
func (UnimplementedBpfmanServer) List(context.Context, *ListRequest) (*ListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedBpfmanServer) PullBytecode(context.Context, *PullBytecodeRequest) (*PullBytecodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PullBytecode not implemented")
}
func (UnimplementedBpfmanServer) Get(context.Context, *GetRequest) (*GetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedBpfmanServer) mustEmbedUnimplementedBpfmanServer() {}

// UnsafeBpfmanServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BpfmanServer will
// result in compilation errors.
type UnsafeBpfmanServer interface {
	mustEmbedUnimplementedBpfmanServer()
}

func RegisterBpfmanServer(s grpc.ServiceRegistrar, srv BpfmanServer) {
	s.RegisterService(&Bpfman_ServiceDesc, srv)
}

func _Bpfman_Load_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).Load(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/Load",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).Load(ctx, req.(*LoadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bpfman_Unload_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnloadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).Unload(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/Unload",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).Unload(ctx, req.(*UnloadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bpfman_Attach_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttachRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).Attach(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/Attach",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).Attach(ctx, req.(*AttachRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bpfman_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).List(ctx, req.(*ListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bpfman_PullBytecode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PullBytecodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).PullBytecode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/PullBytecode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).PullBytecode(ctx, req.(*PullBytecodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bpfman_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BpfmanServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bpfman.v1.Bpfman/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BpfmanServer).Get(ctx, req.(*GetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Bpfman_ServiceDesc is the grpc.ServiceDesc for Bpfman service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Bpfman_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "bpfman.v1.Bpfman",
	HandlerType: (*BpfmanServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Load",
			Handler:    _Bpfman_Load_Handler,
		},
		{
			MethodName: "Unload",
			Handler:    _Bpfman_Unload_Handler,
		},
		{
			MethodName: "Attach",
			Handler:    _Bpfman_Attach_Handler,
		},
		{
			MethodName: "List",
			Handler:    _Bpfman_List_Handler,
		},
		{
			MethodName: "PullBytecode",
			Handler:    _Bpfman_PullBytecode_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _Bpfman_Get_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bpfman.proto",
}
