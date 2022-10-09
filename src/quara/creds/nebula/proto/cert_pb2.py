# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: cert.proto

import sys

_b = sys.version_info[0] < 3 and (lambda x: x) or (lambda x: x.encode("latin1"))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor.FileDescriptor(
    name="cert.proto",
    package="cert",
    syntax="proto3",
    serialized_options=_b("Z\036github.com/slackhq/nebula/cert"),
    serialized_pb=_b(
        '\n\ncert.proto\x12\x04\x63\x65rt"]\n\x14RawNebulaCertificate\x12\x32\n\x07\x44\x65tails\x18\x01 \x01(\x0b\x32!.cert.RawNebulaCertificateDetails\x12\x11\n\tSignature\x18\x02 \x01(\x0c"\xaf\x01\n\x1bRawNebulaCertificateDetails\x12\x0c\n\x04Name\x18\x01 \x01(\t\x12\x0b\n\x03Ips\x18\x02 \x03(\r\x12\x0f\n\x07Subnets\x18\x03 \x03(\r\x12\x0e\n\x06Groups\x18\x04 \x03(\t\x12\x11\n\tNotBefore\x18\x05 \x01(\x03\x12\x10\n\x08NotAfter\x18\x06 \x01(\x03\x12\x11\n\tPublicKey\x18\x07 \x01(\x0c\x12\x0c\n\x04IsCA\x18\x08 \x01(\x08\x12\x0e\n\x06Issuer\x18\t \x01(\x0c\x42 Z\x1egithub.com/slackhq/nebula/certb\x06proto3'
    ),
)


_RAWNEBULACERTIFICATE = _descriptor.Descriptor(
    name="RawNebulaCertificate",
    full_name="cert.RawNebulaCertificate",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="Details",
            full_name="cert.RawNebulaCertificate.Details",
            index=0,
            number=1,
            type=11,
            cpp_type=10,
            label=1,
            has_default_value=False,
            default_value=None,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="Signature",
            full_name="cert.RawNebulaCertificate.Signature",
            index=1,
            number=2,
            type=12,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b(""),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=20,
    serialized_end=113,
)


_RAWNEBULACERTIFICATEDETAILS = _descriptor.Descriptor(
    name="RawNebulaCertificateDetails",
    full_name="cert.RawNebulaCertificateDetails",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="Name",
            full_name="cert.RawNebulaCertificateDetails.Name",
            index=0,
            number=1,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="Ips",
            full_name="cert.RawNebulaCertificateDetails.Ips",
            index=1,
            number=2,
            type=13,
            cpp_type=3,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="Subnets",
            full_name="cert.RawNebulaCertificateDetails.Subnets",
            index=2,
            number=3,
            type=13,
            cpp_type=3,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="Groups",
            full_name="cert.RawNebulaCertificateDetails.Groups",
            index=3,
            number=4,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="NotBefore",
            full_name="cert.RawNebulaCertificateDetails.NotBefore",
            index=4,
            number=5,
            type=3,
            cpp_type=2,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="NotAfter",
            full_name="cert.RawNebulaCertificateDetails.NotAfter",
            index=5,
            number=6,
            type=3,
            cpp_type=2,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="PublicKey",
            full_name="cert.RawNebulaCertificateDetails.PublicKey",
            index=6,
            number=7,
            type=12,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b(""),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="IsCA",
            full_name="cert.RawNebulaCertificateDetails.IsCA",
            index=7,
            number=8,
            type=8,
            cpp_type=7,
            label=1,
            has_default_value=False,
            default_value=False,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="Issuer",
            full_name="cert.RawNebulaCertificateDetails.Issuer",
            index=8,
            number=9,
            type=12,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b(""),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=116,
    serialized_end=291,
)

_RAWNEBULACERTIFICATE.fields_by_name[
    "Details"
].message_type = _RAWNEBULACERTIFICATEDETAILS
DESCRIPTOR.message_types_by_name["RawNebulaCertificate"] = _RAWNEBULACERTIFICATE
DESCRIPTOR.message_types_by_name[
    "RawNebulaCertificateDetails"
] = _RAWNEBULACERTIFICATEDETAILS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RawNebulaCertificate = _reflection.GeneratedProtocolMessageType(
    "RawNebulaCertificate",
    (_message.Message,),
    dict(
        DESCRIPTOR=_RAWNEBULACERTIFICATE,
        __module__="cert_pb2"
        # @@protoc_insertion_point(class_scope:cert.RawNebulaCertificate)
    ),
)
_sym_db.RegisterMessage(RawNebulaCertificate)

RawNebulaCertificateDetails = _reflection.GeneratedProtocolMessageType(
    "RawNebulaCertificateDetails",
    (_message.Message,),
    dict(
        DESCRIPTOR=_RAWNEBULACERTIFICATEDETAILS,
        __module__="cert_pb2"
        # @@protoc_insertion_point(class_scope:cert.RawNebulaCertificateDetails)
    ),
)
_sym_db.RegisterMessage(RawNebulaCertificateDetails)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)