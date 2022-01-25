// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: src/main/java/publicKeyEnc.proto

public final class PublicKeyEncOuterClass {
  private PublicKeyEncOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface PublicKeyEncOrBuilder extends
      // @@protoc_insertion_point(interface_extends:PublicKeyEnc)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @return A list containing the encodedPublicKey.
     */
    java.util.List<com.google.protobuf.ByteString> getEncodedPublicKeyList();
    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @return The count of encodedPublicKey.
     */
    int getEncodedPublicKeyCount();
    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @param index The index of the element to return.
     * @return The encodedPublicKey at the given index.
     */
    com.google.protobuf.ByteString getEncodedPublicKey(int index);
  }
  /**
   * Protobuf type {@code PublicKeyEnc}
   */
  public static final class PublicKeyEnc extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:PublicKeyEnc)
      PublicKeyEncOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use PublicKeyEnc.newBuilder() to construct.
    private PublicKeyEnc(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private PublicKeyEnc() {
      encodedPublicKey_ = java.util.Collections.emptyList();
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new PublicKeyEnc();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private PublicKeyEnc(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 10: {
              if (!((mutable_bitField0_ & 0x00000001) != 0)) {
                encodedPublicKey_ = new java.util.ArrayList<com.google.protobuf.ByteString>();
                mutable_bitField0_ |= 0x00000001;
              }
              encodedPublicKey_.add(input.readBytes());
              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        if (((mutable_bitField0_ & 0x00000001) != 0)) {
          encodedPublicKey_ = java.util.Collections.unmodifiableList(encodedPublicKey_); // C
        }
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return PublicKeyEncOuterClass.internal_static_PublicKeyEnc_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return PublicKeyEncOuterClass.internal_static_PublicKeyEnc_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              PublicKeyEncOuterClass.PublicKeyEnc.class, PublicKeyEncOuterClass.PublicKeyEnc.Builder.class);
    }

    public static final int ENCODEDPUBLICKEY_FIELD_NUMBER = 1;
    private java.util.List<com.google.protobuf.ByteString> encodedPublicKey_;
    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @return A list containing the encodedPublicKey.
     */
    @java.lang.Override
    public java.util.List<com.google.protobuf.ByteString>
        getEncodedPublicKeyList() {
      return encodedPublicKey_;
    }
    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @return The count of encodedPublicKey.
     */
    public int getEncodedPublicKeyCount() {
      return encodedPublicKey_.size();
    }
    /**
     * <code>repeated bytes encodedPublicKey = 1;</code>
     * @param index The index of the element to return.
     * @return The encodedPublicKey at the given index.
     */
    public com.google.protobuf.ByteString getEncodedPublicKey(int index) {
      return encodedPublicKey_.get(index);
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      for (int i = 0; i < encodedPublicKey_.size(); i++) {
        output.writeBytes(1, encodedPublicKey_.get(i));
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      {
        int dataSize = 0;
        for (int i = 0; i < encodedPublicKey_.size(); i++) {
          dataSize += com.google.protobuf.CodedOutputStream
            .computeBytesSizeNoTag(encodedPublicKey_.get(i));
        }
        size += dataSize;
        size += 1 * getEncodedPublicKeyList().size();
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof PublicKeyEncOuterClass.PublicKeyEnc)) {
        return super.equals(obj);
      }
      PublicKeyEncOuterClass.PublicKeyEnc other = (PublicKeyEncOuterClass.PublicKeyEnc) obj;

      if (!getEncodedPublicKeyList()
          .equals(other.getEncodedPublicKeyList())) return false;
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      if (getEncodedPublicKeyCount() > 0) {
        hash = (37 * hash) + ENCODEDPUBLICKEY_FIELD_NUMBER;
        hash = (53 * hash) + getEncodedPublicKeyList().hashCode();
      }
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static PublicKeyEncOuterClass.PublicKeyEnc parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(PublicKeyEncOuterClass.PublicKeyEnc prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code PublicKeyEnc}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:PublicKeyEnc)
        PublicKeyEncOuterClass.PublicKeyEncOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return PublicKeyEncOuterClass.internal_static_PublicKeyEnc_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return PublicKeyEncOuterClass.internal_static_PublicKeyEnc_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                PublicKeyEncOuterClass.PublicKeyEnc.class, PublicKeyEncOuterClass.PublicKeyEnc.Builder.class);
      }

      // Construct using PublicKeyEncOuterClass.PublicKeyEnc.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        encodedPublicKey_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return PublicKeyEncOuterClass.internal_static_PublicKeyEnc_descriptor;
      }

      @java.lang.Override
      public PublicKeyEncOuterClass.PublicKeyEnc getDefaultInstanceForType() {
        return PublicKeyEncOuterClass.PublicKeyEnc.getDefaultInstance();
      }

      @java.lang.Override
      public PublicKeyEncOuterClass.PublicKeyEnc build() {
        PublicKeyEncOuterClass.PublicKeyEnc result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public PublicKeyEncOuterClass.PublicKeyEnc buildPartial() {
        PublicKeyEncOuterClass.PublicKeyEnc result = new PublicKeyEncOuterClass.PublicKeyEnc(this);
        int from_bitField0_ = bitField0_;
        if (((bitField0_ & 0x00000001) != 0)) {
          encodedPublicKey_ = java.util.Collections.unmodifiableList(encodedPublicKey_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.encodedPublicKey_ = encodedPublicKey_;
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof PublicKeyEncOuterClass.PublicKeyEnc) {
          return mergeFrom((PublicKeyEncOuterClass.PublicKeyEnc)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(PublicKeyEncOuterClass.PublicKeyEnc other) {
        if (other == PublicKeyEncOuterClass.PublicKeyEnc.getDefaultInstance()) return this;
        if (!other.encodedPublicKey_.isEmpty()) {
          if (encodedPublicKey_.isEmpty()) {
            encodedPublicKey_ = other.encodedPublicKey_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureEncodedPublicKeyIsMutable();
            encodedPublicKey_.addAll(other.encodedPublicKey_);
          }
          onChanged();
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        PublicKeyEncOuterClass.PublicKeyEnc parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (PublicKeyEncOuterClass.PublicKeyEnc) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }
      private int bitField0_;

      private java.util.List<com.google.protobuf.ByteString> encodedPublicKey_ = java.util.Collections.emptyList();
      private void ensureEncodedPublicKeyIsMutable() {
        if (!((bitField0_ & 0x00000001) != 0)) {
          encodedPublicKey_ = new java.util.ArrayList<com.google.protobuf.ByteString>(encodedPublicKey_);
          bitField0_ |= 0x00000001;
         }
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @return A list containing the encodedPublicKey.
       */
      public java.util.List<com.google.protobuf.ByteString>
          getEncodedPublicKeyList() {
        return ((bitField0_ & 0x00000001) != 0) ?
                 java.util.Collections.unmodifiableList(encodedPublicKey_) : encodedPublicKey_;
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @return The count of encodedPublicKey.
       */
      public int getEncodedPublicKeyCount() {
        return encodedPublicKey_.size();
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @param index The index of the element to return.
       * @return The encodedPublicKey at the given index.
       */
      public com.google.protobuf.ByteString getEncodedPublicKey(int index) {
        return encodedPublicKey_.get(index);
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @param index The index to set the value at.
       * @param value The encodedPublicKey to set.
       * @return This builder for chaining.
       */
      public Builder setEncodedPublicKey(
          int index, com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  ensureEncodedPublicKeyIsMutable();
        encodedPublicKey_.set(index, value);
        onChanged();
        return this;
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @param value The encodedPublicKey to add.
       * @return This builder for chaining.
       */
      public Builder addEncodedPublicKey(com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  ensureEncodedPublicKeyIsMutable();
        encodedPublicKey_.add(value);
        onChanged();
        return this;
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @param values The encodedPublicKey to add.
       * @return This builder for chaining.
       */
      public Builder addAllEncodedPublicKey(
          java.lang.Iterable<? extends com.google.protobuf.ByteString> values) {
        ensureEncodedPublicKeyIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, encodedPublicKey_);
        onChanged();
        return this;
      }
      /**
       * <code>repeated bytes encodedPublicKey = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearEncodedPublicKey() {
        encodedPublicKey_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
        return this;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:PublicKeyEnc)
    }

    // @@protoc_insertion_point(class_scope:PublicKeyEnc)
    private static final PublicKeyEncOuterClass.PublicKeyEnc DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new PublicKeyEncOuterClass.PublicKeyEnc();
    }

    public static PublicKeyEncOuterClass.PublicKeyEnc getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<PublicKeyEnc>
        PARSER = new com.google.protobuf.AbstractParser<PublicKeyEnc>() {
      @java.lang.Override
      public PublicKeyEnc parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new PublicKeyEnc(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<PublicKeyEnc> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<PublicKeyEnc> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public PublicKeyEncOuterClass.PublicKeyEnc getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_PublicKeyEnc_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_PublicKeyEnc_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n src/main/java/publicKeyEnc.proto\"(\n\014Pu" +
      "blicKeyEnc\022\030\n\020encodedPublicKey\030\001 \003(\014b\006pr" +
      "oto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_PublicKeyEnc_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_PublicKeyEnc_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_PublicKeyEnc_descriptor,
        new java.lang.String[] { "EncodedPublicKey", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}