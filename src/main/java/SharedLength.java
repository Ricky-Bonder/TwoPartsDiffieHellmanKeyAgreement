// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: src/main/java/sharedLength.proto

public final class SharedLength {
  private SharedLength() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface sharedSecretLengthOrBuilder extends
      // @@protoc_insertion_point(interface_extends:sharedSecretLength)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>uint64 sharedSecretLen = 1;</code>
     * @return The sharedSecretLen.
     */
    long getSharedSecretLen();
  }
  /**
   * Protobuf type {@code sharedSecretLength}
   */
  public static final class sharedSecretLength extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:sharedSecretLength)
      sharedSecretLengthOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use sharedSecretLength.newBuilder() to construct.
    private sharedSecretLength(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private sharedSecretLength() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new sharedSecretLength();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private sharedSecretLength(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
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
            case 8: {

              sharedSecretLen_ = input.readUInt64();
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
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return SharedLength.internal_static_sharedSecretLength_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return SharedLength.internal_static_sharedSecretLength_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              SharedLength.sharedSecretLength.class, SharedLength.sharedSecretLength.Builder.class);
    }

    public static final int SHAREDSECRETLEN_FIELD_NUMBER = 1;
    private long sharedSecretLen_;
    /**
     * <code>uint64 sharedSecretLen = 1;</code>
     * @return The sharedSecretLen.
     */
    @java.lang.Override
    public long getSharedSecretLen() {
      return sharedSecretLen_;
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
      if (sharedSecretLen_ != 0L) {
        output.writeUInt64(1, sharedSecretLen_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (sharedSecretLen_ != 0L) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt64Size(1, sharedSecretLen_);
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
      if (!(obj instanceof SharedLength.sharedSecretLength)) {
        return super.equals(obj);
      }
      SharedLength.sharedSecretLength other = (SharedLength.sharedSecretLength) obj;

      if (getSharedSecretLen()
          != other.getSharedSecretLen()) return false;
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
      hash = (37 * hash) + SHAREDSECRETLEN_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          getSharedSecretLen());
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static SharedLength.sharedSecretLength parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static SharedLength.sharedSecretLength parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static SharedLength.sharedSecretLength parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static SharedLength.sharedSecretLength parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static SharedLength.sharedSecretLength parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static SharedLength.sharedSecretLength parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static SharedLength.sharedSecretLength parseFrom(
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
    public static Builder newBuilder(SharedLength.sharedSecretLength prototype) {
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
     * Protobuf type {@code sharedSecretLength}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:sharedSecretLength)
        SharedLength.sharedSecretLengthOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return SharedLength.internal_static_sharedSecretLength_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return SharedLength.internal_static_sharedSecretLength_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                SharedLength.sharedSecretLength.class, SharedLength.sharedSecretLength.Builder.class);
      }

      // Construct using SharedLength.sharedSecretLength.newBuilder()
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
        sharedSecretLen_ = 0L;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return SharedLength.internal_static_sharedSecretLength_descriptor;
      }

      @java.lang.Override
      public SharedLength.sharedSecretLength getDefaultInstanceForType() {
        return SharedLength.sharedSecretLength.getDefaultInstance();
      }

      @java.lang.Override
      public SharedLength.sharedSecretLength build() {
        SharedLength.sharedSecretLength result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public SharedLength.sharedSecretLength buildPartial() {
        SharedLength.sharedSecretLength result = new SharedLength.sharedSecretLength(this);
        result.sharedSecretLen_ = sharedSecretLen_;
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
        if (other instanceof SharedLength.sharedSecretLength) {
          return mergeFrom((SharedLength.sharedSecretLength)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(SharedLength.sharedSecretLength other) {
        if (other == SharedLength.sharedSecretLength.getDefaultInstance()) return this;
        if (other.getSharedSecretLen() != 0L) {
          setSharedSecretLen(other.getSharedSecretLen());
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
        SharedLength.sharedSecretLength parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (SharedLength.sharedSecretLength) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private long sharedSecretLen_ ;
      /**
       * <code>uint64 sharedSecretLen = 1;</code>
       * @return The sharedSecretLen.
       */
      @java.lang.Override
      public long getSharedSecretLen() {
        return sharedSecretLen_;
      }
      /**
       * <code>uint64 sharedSecretLen = 1;</code>
       * @param value The sharedSecretLen to set.
       * @return This builder for chaining.
       */
      public Builder setSharedSecretLen(long value) {
        
        sharedSecretLen_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint64 sharedSecretLen = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearSharedSecretLen() {
        
        sharedSecretLen_ = 0L;
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


      // @@protoc_insertion_point(builder_scope:sharedSecretLength)
    }

    // @@protoc_insertion_point(class_scope:sharedSecretLength)
    private static final SharedLength.sharedSecretLength DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new SharedLength.sharedSecretLength();
    }

    public static SharedLength.sharedSecretLength getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<sharedSecretLength>
        PARSER = new com.google.protobuf.AbstractParser<sharedSecretLength>() {
      @java.lang.Override
      public sharedSecretLength parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new sharedSecretLength(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<sharedSecretLength> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<sharedSecretLength> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public SharedLength.sharedSecretLength getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_sharedSecretLength_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_sharedSecretLength_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n src/main/java/sharedLength.proto\"-\n\022sh" +
      "aredSecretLength\022\027\n\017sharedSecretLen\030\001 \001(" +
      "\004b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_sharedSecretLength_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_sharedSecretLength_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_sharedSecretLength_descriptor,
        new java.lang.String[] { "SharedSecretLen", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
