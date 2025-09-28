// WebGPU Type Definitions
declare global {
  interface Navigator {
    gpu?: GPU;
  }

  interface WorkerNavigator {
    gpu?: GPU;
  }

  interface Window {
    navigator: Navigator;
  }

  interface GPU {
    requestAdapter(options?: GPURequestAdapterOptions): Promise<GPUAdapter | null>;
  }

  interface GPURequestAdapterOptions {
    powerPreference?: GPUPowerPreference;
    forceFallbackAdapter?: boolean;
  }

  type GPUPowerPreference = "low-power" | "high-performance";

  interface GPUAdapter {
    requestDevice(): Promise<GPUDevice>;
  }

  interface GPUDevice {
    createBuffer(descriptor: GPUBufferDescriptor): GPUBuffer;
    createComputePipeline(descriptor: GPUComputePipelineDescriptor): GPUComputePipeline;
    createComputePipelineAsync(descriptor: GPUComputePipelineDescriptor): Promise<GPUComputePipeline>;
    createQuerySet(descriptor: GPUQuerySetDescriptor): GPUQuerySet;
    createShaderModule(descriptor: GPUShaderModuleDescriptor): GPUShaderModule;
    createCommandEncoder(descriptor?: GPUCommandEncoderDescriptor): GPUCommandEncoder;
    createBindGroup(descriptor: GPUBindGroupDescriptor): GPUBindGroup;
    queue: GPUQueue;
    lost: Promise<GPUDeviceLostInfo>;
    destroy(): void;
  }

  interface GPUBuffer {
    mapAsync(mode: GPUMapModeFlags): Promise<void>;
    getMappedRange(): ArrayBuffer;
    unmap(): void;
    destroy(): void;
  }

  interface GPUComputePipeline {
    getBindGroupLayout(index: number): GPUBindGroupLayout;
  }

  interface GPUQuerySet {
    destroy(): void;
  }

  interface GPUQueue {
    submit(commandBuffers: GPUCommandBuffer[]): void;
    writeBuffer(buffer: GPUBuffer, bufferOffset: number, data: BufferSource): void;
  }

  interface GPUShaderModule {
    // Shader module interface
  }

  interface GPUShaderModuleDescriptor {
    code: string;
  }

  interface GPUCommandEncoder {
    beginComputePass(descriptor?: GPUComputePassDescriptor): GPUComputePassEncoder;
    finish(descriptor?: GPUCommandBufferDescriptor): GPUCommandBuffer;
    copyBufferToBuffer(source: GPUBuffer, sourceOffset: number, destination: GPUBuffer, destinationOffset: number, size: number): void;
  }

  interface GPUCommandEncoderDescriptor {
    label?: string;
  }

  interface GPUCommandBuffer {
    // Command buffer interface
  }

  interface GPUCommandBufferDescriptor {
    label?: string;
  }

  interface GPUComputePassEncoder {
    setPipeline(pipeline: GPUComputePipeline): void;
    setBindGroup(index: number, bindGroup: GPUBindGroup): void;
    dispatchWorkgroups(workgroupCountX: number, workgroupCountY?: number, workgroupCountZ?: number): void;
    end(): void;
  }

  interface GPUComputePassDescriptor {
    label?: string;
  }

  interface GPUBindGroup {
    // Bind group interface
  }

  interface GPUBindGroupDescriptor {
    layout: GPUBindGroupLayout;
    entries: GPUBindGroupEntry[];
  }

  interface GPUBindGroupEntry {
    binding: number;
    resource: GPUBindingResource;
  }

  type GPUBindingResource = GPUBufferBinding | GPUSampler | GPUTextureView;

  interface GPUBufferBinding {
    buffer: GPUBuffer;
    offset?: number;
    size?: number;
  }

  interface GPUSampler {
    // Sampler interface
  }

  interface GPUTextureView {
    // Texture view interface
  }

  interface GPUBindGroupLayout {
    // Bind group layout interface
  }

  interface GPUDeviceLostInfo {
    reason: GPUDeviceLostReason;
    message: string;
  }

  type GPUDeviceLostReason = "unknown" | "destroyed";

  interface GPUBufferDescriptor {
    size: number;
    usage: GPUBufferUsageFlags;
    mappedAtCreation?: boolean;
  }

  interface GPUComputePipelineDescriptor {
    // Add properties as needed
  }

  interface GPUQuerySetDescriptor {
    // Add properties as needed
  }

  namespace GPUBufferUsage {
    const MAP_READ: number;
    const MAP_WRITE: number;
    const COPY_SRC: number;
    const COPY_DST: number;
    const INDEX: number;
    const VERTEX: number;
    const UNIFORM: number;
    const STORAGE: number;
    const INDIRECT: number;
    const QUERY_RESOLVE: number;
  }

  enum GPUMapMode {
    READ = 0x0001,
    WRITE = 0x0002,
  }

  type GPUBufferUsageFlags = number;
  type GPUMapModeFlags = number;
}

export {};
