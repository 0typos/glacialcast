//! DMA-BUF readback through EGL and OpenGL ES.
//!
//! Compositors hand screen capture frames to PipeWire as DMA-BUFs whose pixels
//! are laid out in a vendor tiling described by a DRM format modifier. Reading
//! those bytes directly would publish a scrambled picture, and some drivers
//! (notably the proprietary NVIDIA stack) refuse to map an imported buffer
//! through GBM at all. This module asks the GPU to resolve the tiling instead:
//! the descriptor is imported as an `EGLImage`, attached to a framebuffer
//! object, and read back as tightly packed 8-bit RGBA or BGRA pixels.
//!
//! EGL and OpenGL ES are loaded at runtime, exactly like the OpenH264 encoder,
//! so a host without a GPU stack still builds and runs the software paths. All
//! calls after [`EglReadback::new`] must happen on the thread that created the
//! instance, because the EGL context is bound to that thread and the type is
//! deliberately neither `Send` nor `Sync`.

use anyhow::{Context, Result, bail};
use libloading::Library;
use std::{
    ffi::{CStr, CString, c_char, c_void},
    marker::PhantomData,
    os::fd::RawFd,
};
use tracing::{debug, warn};

/// Byte order of the pixels produced by [`EglReadback::read_dmabuf`].
///
/// Each pixel is four bytes wide. The fourth byte is whatever the driver
/// reports for the alpha channel and must be ignored for opaque sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadbackLayout {
    /// Bytes are ordered red, green, blue, alpha.
    Rgba,
    /// Bytes are ordered blue, green, red, alpha.
    Bgra,
}

/// A single-plane DMA-BUF frame to read back.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DmaBufPlane {
    /// Borrowed descriptor owned by the capture buffer; only read during the call.
    pub(crate) fd: RawFd,
    /// Byte offset of the first pixel inside the descriptor.
    pub(crate) offset: u32,
    /// Distance in bytes between the start of consecutive pixel rows.
    pub(crate) stride: u32,
    /// Frame width in pixels.
    pub(crate) width: u32,
    /// Frame height in pixels.
    pub(crate) height: u32,
    /// DRM `fourcc` describing the untiled pixel format.
    pub(crate) fourcc: u32,
    /// DRM format modifier describing the tiling, or `DRM_FORMAT_MOD_INVALID`.
    pub(crate) modifier: u64,
}

/// Linear pixels produced from one DMA-BUF import.
pub(crate) struct Readback {
    /// Tightly packed pixel rows, `stride * height` bytes long.
    pub(crate) data: Vec<u8>,
    /// Distance in bytes between consecutive rows of `data`.
    pub(crate) stride: usize,
    /// Width of the returned image, which is the requested target only when
    /// the driver scaled it; otherwise it is the source width.
    pub(crate) width: u32,
    /// Height of the returned image, on the same terms as `width`.
    pub(crate) height: u32,
    /// Byte order of each four-byte pixel in `data`.
    pub(crate) layout: ReadbackLayout,
}

const EGL_NONE: i32 = 0x3038;
const EGL_TRUE: u32 = 1;
const EGL_PLATFORM_GBM_KHR: u32 = 0x31D7;
const EGL_OPENGL_ES_API: u32 = 0x30A0;
const EGL_CONTEXT_CLIENT_VERSION: i32 = 0x3098;
const EGL_EXTENSIONS: i32 = 0x3055;
const EGL_LINUX_DMA_BUF_EXT: u32 = 0x3270;
const EGL_LINUX_DRM_FOURCC_EXT: i32 = 0x3271;
const EGL_WIDTH: i32 = 0x3057;
const EGL_HEIGHT: i32 = 0x3056;
const EGL_DMA_BUF_PLANE0_FD_EXT: i32 = 0x3272;
const EGL_DMA_BUF_PLANE0_OFFSET_EXT: i32 = 0x3273;
const EGL_DMA_BUF_PLANE0_PITCH_EXT: i32 = 0x3274;
const EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT: i32 = 0x3443;
const EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT: i32 = 0x3444;
const EGL_IMAGE_PRESERVED_KHR: i32 = 0x30D2;

const GL_TEXTURE_2D: u32 = 0x0DE1;
const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
const GL_TEXTURE_WRAP_S: u32 = 0x2802;
const GL_TEXTURE_WRAP_T: u32 = 0x2803;
const GL_NEAREST: i32 = 0x2600;
const GL_CLAMP_TO_EDGE: i32 = 0x812F;
const GL_FRAMEBUFFER: u32 = 0x8D40;
const GL_COLOR_ATTACHMENT0: u32 = 0x8CE0;
const GL_FRAMEBUFFER_COMPLETE: u32 = 0x8CD5;
const GL_RGBA: u32 = 0x1908;
const GL_BGRA_EXT: u32 = 0x80E1;
const GL_UNSIGNED_BYTE: u32 = 0x1401;
const GL_PACK_ALIGNMENT: u32 = 0x0D05;
const GL_IMPLEMENTATION_COLOR_READ_FORMAT: u32 = 0x8B9B;
const GL_IMPLEMENTATION_COLOR_READ_TYPE: u32 = 0x8B9A;
const GL_NO_ERROR: u32 = 0;
const GL_LINEAR: i32 = 0x2601;
const GL_VERTEX_SHADER: u32 = 0x8B31;
const GL_FRAGMENT_SHADER: u32 = 0x8B30;
const GL_COMPILE_STATUS: u32 = 0x8B81;
const GL_LINK_STATUS: u32 = 0x8B82;
const GL_FLOAT: u32 = 0x1406;
const GL_TRIANGLE_STRIP: u32 = 0x0005;
const GL_TEXTURE0: u32 = 0x84C0;
const GL_FALSE_U8: u8 = 0;

/// The largest frame this module will allocate a readback buffer for.
///
/// A compositor cannot legitimately hand back more than 8192x8192 pixels here,
/// and the bound keeps a corrupt descriptor from requesting a huge allocation.
const MAX_READBACK_PIXELS: u64 = 8192 * 8192;

type EglGetProcAddress = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type EglGetError = unsafe extern "C" fn() -> i32;
type EglInitialize = unsafe extern "C" fn(*mut c_void, *mut i32, *mut i32) -> u32;
type EglBindApi = unsafe extern "C" fn(u32) -> u32;
type EglQueryString = unsafe extern "C" fn(*mut c_void, i32) -> *const c_char;
type EglCreateContext =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const i32) -> *mut c_void;
type EglDestroyContext = unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32;
type EglMakeCurrent =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> u32;
type EglGetPlatformDisplay = unsafe extern "C" fn(u32, *mut c_void, *const isize) -> *mut c_void;
type EglCreateImage =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void, *const i32) -> *mut c_void;
type EglDestroyImage = unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32;
type GlImageTargetTexture2D = unsafe extern "C" fn(u32, *mut c_void);

type GlGenTextures = unsafe extern "C" fn(i32, *mut u32);
type GlDeleteTextures = unsafe extern "C" fn(i32, *const u32);
type GlBindTexture = unsafe extern "C" fn(u32, u32);
type GlTexParameteri = unsafe extern "C" fn(u32, u32, i32);
type GlGenFramebuffers = unsafe extern "C" fn(i32, *mut u32);
type GlDeleteFramebuffers = unsafe extern "C" fn(i32, *const u32);
type GlBindFramebuffer = unsafe extern "C" fn(u32, u32);
type GlFramebufferTexture2D = unsafe extern "C" fn(u32, u32, u32, u32, i32);
type GlCheckFramebufferStatus = unsafe extern "C" fn(u32) -> u32;
type GlReadPixels = unsafe extern "C" fn(i32, i32, i32, i32, u32, u32, *mut c_void);
type GlPixelStorei = unsafe extern "C" fn(u32, i32);
type GlGetIntegerv = unsafe extern "C" fn(u32, *mut i32);
type GlGetError = unsafe extern "C" fn() -> u32;
type GlFinish = unsafe extern "C" fn();

// Only needed by the scaling pass. They are resolved with the rest so a driver
// missing any of them disables scaling at construction rather than failing
// partway through the first frame.
type GlCreateShader = unsafe extern "C" fn(u32) -> u32;
type GlShaderSource = unsafe extern "C" fn(u32, i32, *const *const c_char, *const i32);
type GlCompileShader = unsafe extern "C" fn(u32);
type GlGetShaderiv = unsafe extern "C" fn(u32, u32, *mut i32);
type GlGetShaderInfoLog = unsafe extern "C" fn(u32, i32, *mut i32, *mut c_char);
type GlDeleteShader = unsafe extern "C" fn(u32);
type GlCreateProgram = unsafe extern "C" fn() -> u32;
type GlAttachShader = unsafe extern "C" fn(u32, u32);
type GlLinkProgram = unsafe extern "C" fn(u32);
type GlGetProgramiv = unsafe extern "C" fn(u32, u32, *mut i32);
type GlGetProgramInfoLog = unsafe extern "C" fn(u32, i32, *mut i32, *mut c_char);
type GlUseProgram = unsafe extern "C" fn(u32);
type GlDeleteProgram = unsafe extern "C" fn(u32);
type GlGetAttribLocation = unsafe extern "C" fn(u32, *const c_char) -> i32;
type GlGetUniformLocation = unsafe extern "C" fn(u32, *const c_char) -> i32;
type GlUniform1i = unsafe extern "C" fn(i32, i32);
type GlVertexAttribPointer = unsafe extern "C" fn(u32, i32, u32, u8, i32, *const c_void);
type GlEnableVertexAttribArray = unsafe extern "C" fn(u32);
type GlDrawArrays = unsafe extern "C" fn(u32, i32, i32);
type GlViewport = unsafe extern "C" fn(i32, i32, i32, i32);
type GlActiveTexture = unsafe extern "C" fn(u32);
type GlTexImage2D = unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void);

/// Runtime-resolved EGL and OpenGL ES entry points.
///
/// The two libraries are kept alive for as long as the entry points are
/// reachable, because unloading a live GL driver is not sound.
struct Entrypoints {
    egl_get_error: EglGetError,
    egl_initialize: EglInitialize,
    egl_bind_api: EglBindApi,
    egl_query_string: EglQueryString,
    egl_create_context: EglCreateContext,
    egl_destroy_context: EglDestroyContext,
    egl_make_current: EglMakeCurrent,
    egl_get_platform_display: EglGetPlatformDisplay,
    egl_create_image: EglCreateImage,
    egl_destroy_image: EglDestroyImage,
    gl_image_target_texture_2d: GlImageTargetTexture2D,
    gl_gen_textures: GlGenTextures,
    gl_delete_textures: GlDeleteTextures,
    gl_bind_texture: GlBindTexture,
    gl_tex_parameteri: GlTexParameteri,
    gl_gen_framebuffers: GlGenFramebuffers,
    gl_delete_framebuffers: GlDeleteFramebuffers,
    gl_bind_framebuffer: GlBindFramebuffer,
    gl_framebuffer_texture_2d: GlFramebufferTexture2D,
    gl_check_framebuffer_status: GlCheckFramebufferStatus,
    gl_read_pixels: GlReadPixels,
    gl_pixel_storei: GlPixelStorei,
    gl_get_integerv: GlGetIntegerv,
    gl_get_error: GlGetError,
    gl_finish: GlFinish,
    scale: Option<ScaleEntrypoints>,
    _gles: Library,
    _egl: Library,
}

/// Entry points used only by the GPU scaling pass.
struct ScaleEntrypoints {
    gl_create_shader: GlCreateShader,
    gl_shader_source: GlShaderSource,
    gl_compile_shader: GlCompileShader,
    gl_get_shaderiv: GlGetShaderiv,
    gl_get_shader_info_log: GlGetShaderInfoLog,
    gl_delete_shader: GlDeleteShader,
    gl_create_program: GlCreateProgram,
    gl_attach_shader: GlAttachShader,
    gl_link_program: GlLinkProgram,
    gl_get_programiv: GlGetProgramiv,
    gl_get_program_info_log: GlGetProgramInfoLog,
    gl_use_program: GlUseProgram,
    gl_delete_program: GlDeleteProgram,
    gl_get_attrib_location: GlGetAttribLocation,
    gl_get_uniform_location: GlGetUniformLocation,
    gl_uniform1i: GlUniform1i,
    gl_vertex_attrib_pointer: GlVertexAttribPointer,
    gl_enable_vertex_attrib_array: GlEnableVertexAttribArray,
    gl_draw_arrays: GlDrawArrays,
    gl_viewport: GlViewport,
    gl_active_texture: GlActiveTexture,
    gl_tex_image_2d: GlTexImage2D,
}

/// Reads a raw library symbol and copies out its function pointer.
///
/// # Safety
///
/// The caller asserts that `name` names a function in `library` whose ABI
/// matches `T`, and that `library` outlives every call through the result.
unsafe fn symbol<T: Copy>(library: &Library, name: &str) -> Result<T> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: the caller guarantees the ABI, `bytes` is NUL terminated, and the
    // copied function pointer is only used while `library` is alive.
    let found = unsafe { library.get::<T>(&bytes) }
        .with_context(|| format!("{name} is missing from the loaded GL stack"))?;
    Ok(*found)
}

/// Resolves an extension entry point through `eglGetProcAddress`.
///
/// # Safety
///
/// The caller asserts that `name` names an EGL or GL extension function whose
/// ABI matches `T`, and that `T` is a plain function pointer type.
unsafe fn proc_address<T: Copy>(get_proc: EglGetProcAddress, name: &str) -> Result<T> {
    let symbol_name = CString::new(name).expect("extension names contain no NUL byte");
    // SAFETY: `symbol_name` stays alive for the call and EGL only reads it.
    let address = unsafe { get_proc(symbol_name.as_ptr()) };
    if address.is_null() {
        bail!("{name} is not provided by this EGL implementation");
    }
    // SAFETY: `T` is a function pointer of the same size as `address`, and the
    // caller guarantees the ABI matches the named entry point.
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&address) })
}

impl Entrypoints {
    /// Loads `libEGL` and `libGLESv2` and resolves every needed entry point.
    fn load() -> Result<Self> {
        // SAFETY: loading a shared library runs its initializers. Both names
        // refer to the system GL stack, which is designed to be dlopened.
        let egl = unsafe { Library::new("libEGL.so.1") }
            .context("loading libEGL.so.1 for DMA-BUF readback")?;
        // SAFETY: as above, for the OpenGL ES client library.
        let gles = unsafe { Library::new("libGLESv2.so.2") }
            .context("loading libGLESv2.so.2 for DMA-BUF readback")?;

        // SAFETY: every name below is resolved from the library that defines
        // it, and each declared signature is transcribed from the EGL 1.5,
        // EGL_KHR_image_base, EGL_KHR_platform_gbm, OES_EGL_image, and OpenGL
        // ES 2.0 specifications. Both libraries are moved into the returned
        // value, so they outlive every copied function pointer.
        unsafe {
            let get_proc: EglGetProcAddress = symbol(&egl, "eglGetProcAddress")?;
            Ok(Self {
                egl_get_error: symbol(&egl, "eglGetError")?,
                egl_initialize: symbol(&egl, "eglInitialize")?,
                egl_bind_api: symbol(&egl, "eglBindAPI")?,
                egl_query_string: symbol(&egl, "eglQueryString")?,
                egl_create_context: symbol(&egl, "eglCreateContext")?,
                egl_destroy_context: symbol(&egl, "eglDestroyContext")?,
                egl_make_current: symbol(&egl, "eglMakeCurrent")?,
                egl_get_platform_display: proc_address(get_proc, "eglGetPlatformDisplayEXT")?,
                egl_create_image: proc_address(get_proc, "eglCreateImageKHR")?,
                egl_destroy_image: proc_address(get_proc, "eglDestroyImageKHR")?,
                gl_image_target_texture_2d: proc_address(get_proc, "glEGLImageTargetTexture2DOES")?,
                gl_gen_textures: symbol(&gles, "glGenTextures")?,
                gl_delete_textures: symbol(&gles, "glDeleteTextures")?,
                gl_bind_texture: symbol(&gles, "glBindTexture")?,
                gl_tex_parameteri: symbol(&gles, "glTexParameteri")?,
                gl_gen_framebuffers: symbol(&gles, "glGenFramebuffers")?,
                gl_delete_framebuffers: symbol(&gles, "glDeleteFramebuffers")?,
                gl_bind_framebuffer: symbol(&gles, "glBindFramebuffer")?,
                gl_framebuffer_texture_2d: symbol(&gles, "glFramebufferTexture2D")?,
                gl_check_framebuffer_status: symbol(&gles, "glCheckFramebufferStatus")?,
                gl_read_pixels: symbol(&gles, "glReadPixels")?,
                gl_pixel_storei: symbol(&gles, "glPixelStorei")?,
                gl_get_integerv: symbol(&gles, "glGetIntegerv")?,
                gl_get_error: symbol(&gles, "glGetError")?,
                gl_finish: symbol(&gles, "glFinish")?,
                // Optional as a group: a stack missing any of these can still
                // read frames back, it just cannot scale them on the GPU.
                scale: ScaleEntrypoints::load(&gles).ok(),
                _gles: gles,
                _egl: egl,
            })
        }
    }
}

impl ScaleEntrypoints {
    /// # Safety
    ///
    /// `gles` must be the OpenGL ES client library, and it must outlive every
    /// copied pointer. The caller moves it into the same owning value.
    unsafe fn load(gles: &Library) -> Result<Self> {
        // SAFETY: every signature below is transcribed from OpenGL ES 2.0, and
        // the caller guarantees the library outlives the pointers.
        unsafe {
            Ok(Self {
                gl_create_shader: symbol(gles, "glCreateShader")?,
                gl_shader_source: symbol(gles, "glShaderSource")?,
                gl_compile_shader: symbol(gles, "glCompileShader")?,
                gl_get_shaderiv: symbol(gles, "glGetShaderiv")?,
                gl_get_shader_info_log: symbol(gles, "glGetShaderInfoLog")?,
                gl_delete_shader: symbol(gles, "glDeleteShader")?,
                gl_create_program: symbol(gles, "glCreateProgram")?,
                gl_attach_shader: symbol(gles, "glAttachShader")?,
                gl_link_program: symbol(gles, "glLinkProgram")?,
                gl_get_programiv: symbol(gles, "glGetProgramiv")?,
                gl_get_program_info_log: symbol(gles, "glGetProgramInfoLog")?,
                gl_use_program: symbol(gles, "glUseProgram")?,
                gl_delete_program: symbol(gles, "glDeleteProgram")?,
                gl_get_attrib_location: symbol(gles, "glGetAttribLocation")?,
                gl_get_uniform_location: symbol(gles, "glGetUniformLocation")?,
                gl_uniform1i: symbol(gles, "glUniform1i")?,
                gl_vertex_attrib_pointer: symbol(gles, "glVertexAttribPointer")?,
                gl_enable_vertex_attrib_array: symbol(gles, "glEnableVertexAttribArray")?,
                gl_draw_arrays: symbol(gles, "glDrawArrays")?,
                gl_viewport: symbol(gles, "glViewport")?,
                gl_active_texture: symbol(gles, "glActiveTexture")?,
                gl_tex_image_2d: symbol(gles, "glTexImage2D")?,
            })
        }
    }
}

/// Draws the imported frame into a smaller framebuffer before it is read back.
///
/// Reading a 2560x1440 frame back and shrinking it on the CPU spends the full
/// source bandwidth to produce a fraction of it. Doing the filtering on the GPU
/// means `glReadPixels` only ever transfers the pixels that are kept.
///
/// Mip levels cannot serve here: a texture bound to an `EGLImage` has level 0
/// and nothing else, so `glGenerateMipmap` has no storage to write into. This
/// is therefore a real draw into a second, ordinary texture.
struct ScalePass {
    program: u32,
    position: u32,
    sampler: i32,
    /// Destination texture and framebuffer, reallocated when the size changes.
    texture: u32,
    framebuffer: u32,
    size: (u32, u32),
}

/// A full-viewport triangle strip in clip space, with texture coordinates
/// derived from position in the vertex shader.
const SCALE_VERTICES: [f32; 8] = [-1.0, -1.0, 1.0, -1.0, -1.0, 1.0, 1.0, 1.0];

const SCALE_VERTEX_SHADER: &str = "attribute vec2 position;\n\
varying vec2 uv;\n\
void main() {\n\
  uv = position * 0.5 + 0.5;\n\
  gl_Position = vec4(position, 0.0, 1.0);\n\
}\n";

const SCALE_FRAGMENT_SHADER: &str = "precision mediump float;\n\
uniform sampler2D source;\n\
varying vec2 uv;\n\
void main() {\n\
  gl_FragColor = texture2D(source, uv);\n\
}\n";

impl ScalePass {
    /// Compiles the program once. Errors leave the caller on the CPU path.
    fn build(gl: &ScaleEntrypoints) -> Result<Self> {
        // SAFETY: a context is current on this thread for every call below,
        // and each shader source is a NUL-terminated string kept alive across
        // its use.
        unsafe {
            let vertex = compile_shader(gl, GL_VERTEX_SHADER, SCALE_VERTEX_SHADER)?;
            let fragment = compile_shader(gl, GL_FRAGMENT_SHADER, SCALE_FRAGMENT_SHADER)?;
            let program = (gl.gl_create_program)();
            if program == 0 {
                (gl.gl_delete_shader)(vertex);
                (gl.gl_delete_shader)(fragment);
                bail!("glCreateProgram returned no program object");
            }
            (gl.gl_attach_shader)(program, vertex);
            (gl.gl_attach_shader)(program, fragment);
            (gl.gl_link_program)(program);
            // The program keeps its own reference once linked.
            (gl.gl_delete_shader)(vertex);
            (gl.gl_delete_shader)(fragment);

            let mut linked = 0;
            (gl.gl_get_programiv)(program, GL_LINK_STATUS, &mut linked);
            if linked == 0 {
                let log = info_log(4096, |length, written, buffer| {
                    (gl.gl_get_program_info_log)(program, length, written, buffer);
                });
                (gl.gl_delete_program)(program);
                bail!("linking the scaling program failed: {log}");
            }

            let position = (gl.gl_get_attrib_location)(program, c"position".as_ptr());
            let sampler = (gl.gl_get_uniform_location)(program, c"source".as_ptr());
            if position < 0 || sampler < 0 {
                (gl.gl_delete_program)(program);
                bail!("the scaling program is missing its position or sampler binding");
            }
            Ok(Self {
                program,
                position: position as u32,
                sampler,
                texture: 0,
                framebuffer: 0,
                size: (0, 0),
            })
        }
    }
}

/// Compiles one shader stage and reports the driver's own diagnostic.
///
/// # Safety
///
/// A GL context must be current on the calling thread.
unsafe fn compile_shader(gl: &ScaleEntrypoints, stage: u32, source: &str) -> Result<u32> {
    let mut bytes = source.as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: the caller guarantees a current context; `bytes` is NUL
    // terminated and outlives the glShaderSource call that reads it.
    unsafe {
        let shader = (gl.gl_create_shader)(stage);
        if shader == 0 {
            bail!("glCreateShader returned no shader object for stage {stage:#x}");
        }
        let pointer = bytes.as_ptr().cast::<c_char>();
        (gl.gl_shader_source)(shader, 1, &raw const pointer, std::ptr::null());
        (gl.gl_compile_shader)(shader);
        let mut compiled = 0;
        (gl.gl_get_shaderiv)(shader, GL_COMPILE_STATUS, &mut compiled);
        if compiled == 0 {
            let log = info_log(4096, |length, written, buffer| {
                (gl.gl_get_shader_info_log)(shader, length, written, buffer);
            });
            (gl.gl_delete_shader)(shader);
            bail!("compiling the scaling shader failed: {log}");
        }
        Ok(shader)
    }
}

/// Collects a driver info log into a lossy `String`.
fn info_log(capacity: i32, fill: impl FnOnce(i32, *mut i32, *mut c_char)) -> String {
    let mut buffer = vec![0i8; capacity as usize];
    let mut written = 0;
    fill(capacity, &raw mut written, buffer.as_mut_ptr());
    let length = written.clamp(0, capacity - 1) as usize;
    String::from_utf8_lossy(
        &buffer[..length]
            .iter()
            .map(|b| *b as u8)
            .collect::<Vec<_>>(),
    )
    .into_owned()
}

/// A GPU-backed DMA-BUF reader bound to one thread and one render device.
pub(crate) struct EglReadback {
    entrypoints: Entrypoints,
    display: *mut c_void,
    context: *mut c_void,
    texture: u32,
    framebuffer: u32,
    read_format: u32,
    layout: ReadbackLayout,
    /// Built on first use; `None` once the driver has refused it, so a
    /// rejection costs one attempt rather than one per frame.
    scale: Option<ScalePass>,
    scale_unavailable: bool,
    /// Human-readable driver identity, for one-time operator logging.
    renderer: String,
    /// `EglReadback` owns thread-affine EGL state and must not cross threads.
    _not_send: PhantomData<*const ()>,
}

impl EglReadback {
    /// Creates a surfaceless OpenGL ES context on `gbm_device`.
    ///
    /// `gbm_device` must be a live `struct gbm_device *` for the render node
    /// that produced the DMA-BUFs; the caller keeps it alive for the lifetime
    /// of the returned value. The context is made current on the calling
    /// thread and every later call must happen on that same thread.
    ///
    /// # Errors
    ///
    /// Returns an error when the GL stack is absent, when the driver lacks
    /// `EGL_EXT_image_dma_buf_import_modifiers` or surfaceless contexts, or
    /// when context creation fails.
    ///
    /// # Safety
    ///
    /// `gbm_device` must be a valid, live GBM device pointer.
    pub(crate) unsafe fn new(gbm_device: *mut c_void) -> Result<Self> {
        let entrypoints = Entrypoints::load()?;
        // SAFETY: the caller guarantees `gbm_device` is a live GBM device, and
        // a NULL attribute list requests the platform defaults.
        let display = unsafe {
            (entrypoints.egl_get_platform_display)(
                EGL_PLATFORM_GBM_KHR,
                gbm_device,
                std::ptr::null(),
            )
        };
        if display.is_null() {
            bail!(
                "eglGetPlatformDisplayEXT rejected the render node (EGL error {:#x})",
                // SAFETY: querying the thread's last EGL error takes no arguments.
                unsafe { (entrypoints.egl_get_error)() }
            );
        }
        let mut major = 0;
        let mut minor = 0;
        // SAFETY: `display` is a valid EGL display and both out-parameters are
        // writable for one `EGLint`.
        if unsafe { (entrypoints.egl_initialize)(display, &mut major, &mut minor) } != EGL_TRUE {
            bail!(
                "eglInitialize failed for the render node (EGL error {:#x})",
                // SAFETY: as above.
                unsafe { (entrypoints.egl_get_error)() }
            );
        }
        // SAFETY: `display` is initialized and `EGL_EXTENSIONS` is a valid query.
        let extensions = unsafe { (entrypoints.egl_query_string)(display, EGL_EXTENSIONS) };
        let extensions = if extensions.is_null() {
            String::new()
        } else {
            // SAFETY: EGL returns a NUL-terminated string owned by the driver
            // and valid until the display is terminated.
            unsafe { CStr::from_ptr(extensions) }
                .to_string_lossy()
                .into_owned()
        };
        for required in [
            "EGL_EXT_image_dma_buf_import",
            "EGL_EXT_image_dma_buf_import_modifiers",
            "EGL_KHR_surfaceless_context",
        ] {
            if !has_extension(&extensions, required) {
                bail!("EGL driver does not advertise {required}");
            }
        }
        let no_config = has_extension(&extensions, "EGL_KHR_no_config_context");
        if !no_config {
            bail!("EGL driver does not advertise EGL_KHR_no_config_context");
        }
        // SAFETY: binding the OpenGL ES API takes a plain enum.
        if unsafe { (entrypoints.egl_bind_api)(EGL_OPENGL_ES_API) } != EGL_TRUE {
            bail!("eglBindAPI(EGL_OPENGL_ES_API) failed");
        }
        let context_attributes = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE];
        // SAFETY: `display` is initialized, a NULL config is legal under
        // EGL_KHR_no_config_context, there is no shared context, and the
        // attribute list is NUL-terminated by `EGL_NONE`.
        let context = unsafe {
            (entrypoints.egl_create_context)(
                display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                context_attributes.as_ptr(),
            )
        };
        if context.is_null() {
            bail!(
                "eglCreateContext failed (EGL error {:#x})",
                // SAFETY: as above.
                unsafe { (entrypoints.egl_get_error)() }
            );
        }
        // SAFETY: surfaceless contexts accept NULL draw and read surfaces.
        if unsafe {
            (entrypoints.egl_make_current)(
                display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                context,
            )
        } != EGL_TRUE
        {
            bail!(
                "eglMakeCurrent failed for the surfaceless context (EGL error {:#x})",
                // SAFETY: as above.
                unsafe { (entrypoints.egl_get_error)() }
            );
        }

        let mut texture = 0;
        let mut framebuffer = 0;
        // SAFETY: a context is current and both out-parameters are writable.
        unsafe {
            (entrypoints.gl_gen_textures)(1, &mut texture);
            (entrypoints.gl_gen_framebuffers)(1, &mut framebuffer);
            (entrypoints.gl_pixel_storei)(GL_PACK_ALIGNMENT, 1);
        }
        if texture == 0 || framebuffer == 0 {
            bail!("OpenGL ES did not allocate the readback texture or framebuffer");
        }
        let renderer = format!("EGL {major}.{minor}");
        Ok(Self {
            entrypoints,
            display,
            context,
            texture,
            framebuffer,
            read_format: GL_RGBA,
            layout: ReadbackLayout::Rgba,
            scale: None,
            scale_unavailable: false,
            renderer,
            _not_send: PhantomData,
        })
    }

    /// Describes the loaded driver for one-time operator logging.
    pub(crate) fn describe(&self) -> &str {
        &self.renderer
    }

    /// Imports `plane` and returns tightly packed linear pixels.
    ///
    /// The returned stride is always `width * 4`. `plane.fd` is only borrowed
    /// for the duration of the call; EGL duplicates whatever it needs.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is invalid, when the driver
    /// refuses the import, or when the framebuffer is not renderable.
    /// Reads the frame back at `target_width` x `target_height`.
    ///
    /// When the target is smaller than the source the shrink happens on the
    /// GPU, so `glReadPixels` transfers only the pixels that are kept. A driver
    /// that cannot do that falls back to reading the full frame, and the caller
    /// scales it as before; the returned `Readback` says which happened through
    /// its extent.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is invalid or when the full-size
    /// readback itself fails. A scaling failure alone is not an error.
    pub(crate) fn read_dmabuf_scaled(
        &mut self,
        plane: &DmaBufPlane,
        target_width: u32,
        target_height: u32,
    ) -> Result<Readback> {
        if plane.fd < 0 {
            bail!("PipeWire supplied an invalid DMA-BUF descriptor");
        }
        if plane.width == 0 || plane.height == 0 {
            bail!(
                "DMA-BUF frame has an empty {}x{} extent",
                plane.width,
                plane.height
            );
        }
        let pixels = u64::from(plane.width) * u64::from(plane.height);
        if pixels > MAX_READBACK_PIXELS {
            bail!(
                "refusing DMA-BUF readback of {}x{}; above the {MAX_READBACK_PIXELS}-pixel bound",
                plane.width,
                plane.height
            );
        }
        let width = i32::try_from(plane.width).context("DMA-BUF width exceeds GL limits")?;
        let height = i32::try_from(plane.height).context("DMA-BUF height exceeds GL limits")?;
        let offset = i32::try_from(plane.offset).context("DMA-BUF offset exceeds EGL limits")?;
        let stride = i32::try_from(plane.stride).context("DMA-BUF stride exceeds EGL limits")?;
        let fourcc = i32::from_ne_bytes(plane.fourcc.to_ne_bytes());

        let mut attributes = vec![
            EGL_WIDTH,
            width,
            EGL_HEIGHT,
            height,
            EGL_LINUX_DRM_FOURCC_EXT,
            fourcc,
            EGL_DMA_BUF_PLANE0_FD_EXT,
            plane.fd,
            EGL_DMA_BUF_PLANE0_OFFSET_EXT,
            offset,
            EGL_DMA_BUF_PLANE0_PITCH_EXT,
            stride,
            EGL_IMAGE_PRESERVED_KHR,
            EGL_TRUE as i32,
        ];
        if plane.modifier != DRM_FORMAT_MOD_INVALID {
            attributes.extend_from_slice(&[
                EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT,
                (plane.modifier & 0xFFFF_FFFF) as u32 as i32,
                EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT,
                (plane.modifier >> 32) as u32 as i32,
            ]);
        }
        attributes.push(EGL_NONE);

        // SAFETY: the attribute list is `EGL_NONE` terminated, `self.display`
        // is initialized, and EGL_EXT_image_dma_buf_import requires a NULL
        // context and client buffer for this target.
        let image = unsafe {
            (self.entrypoints.egl_create_image)(
                self.display,
                std::ptr::null_mut(),
                EGL_LINUX_DMA_BUF_EXT,
                std::ptr::null_mut(),
                attributes.as_ptr(),
            )
        };
        if image.is_null() {
            bail!(
                "eglCreateImageKHR rejected the DMA-BUF (modifier {:#018x}, EGL error {:#x})",
                plane.modifier,
                // SAFETY: querying the thread's last EGL error takes no arguments.
                unsafe { (self.entrypoints.egl_get_error)() }
            );
        }
        let image = EglImageGuard {
            display: self.display,
            image,
            destroy: self.entrypoints.egl_destroy_image,
        };

        let result = self.read_image(
            image.image,
            plane.width,
            plane.height,
            target_width,
            target_height,
        );
        drop(image);
        result
    }

    /// Binds `image` to the reusable texture and reads the framebuffer back.
    fn read_image(
        &mut self,
        image: *mut c_void,
        width: u32,
        height: u32,
        target_width: u32,
        target_height: u32,
    ) -> Result<Readback> {
        let scaling = (target_width, target_height) != (width, height)
            && target_width > 0
            && target_height > 0
            && target_width <= width
            && target_height <= height
            && self.ensure_scale_pass();

        // SAFETY: a context is current on this thread, `self.texture` and
        // `self.framebuffer` were generated by this context, and `image` is a
        // live EGLImage for the duration of the call.
        unsafe {
            (self.entrypoints.gl_bind_texture)(GL_TEXTURE_2D, self.texture);
            // Minifying with GL_NEAREST would alias; a straight readback is
            // one-to-one and does not care either way.
            let filter = if scaling { GL_LINEAR } else { GL_NEAREST };
            (self.entrypoints.gl_tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
            (self.entrypoints.gl_tex_parameteri)(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);
            (self.entrypoints.gl_tex_parameteri)(
                GL_TEXTURE_2D,
                GL_TEXTURE_WRAP_S,
                GL_CLAMP_TO_EDGE,
            );
            (self.entrypoints.gl_tex_parameteri)(
                GL_TEXTURE_2D,
                GL_TEXTURE_WRAP_T,
                GL_CLAMP_TO_EDGE,
            );
            (self.entrypoints.gl_image_target_texture_2d)(GL_TEXTURE_2D, image);
        }
        // SAFETY: taking the current error code has no preconditions beyond a
        // current context.
        let bind_error = unsafe { (self.entrypoints.gl_get_error)() };
        if bind_error != GL_NO_ERROR {
            bail!("glEGLImageTargetTexture2DOES failed with GL error {bind_error:#x}");
        }

        // Scaling renders into its own framebuffer; a plain readback attaches
        // the imported texture directly and reads it where it lies.
        let (read_width, read_height) = if scaling {
            match self.draw_scaled(target_width, target_height) {
                Ok(()) => (target_width, target_height),
                Err(error) => {
                    // One failure disables the pass rather than repeating it
                    // every frame, and the frame itself still gets published
                    // through the unscaled path below.
                    warn!(%error, "GPU frame scaling failed; falling back to full-size readback");
                    self.scale = None;
                    self.scale_unavailable = true;
                    self.attach_source_framebuffer()?;
                    (width, height)
                }
            }
        } else {
            self.attach_source_framebuffer()?;
            (width, height)
        };

        self.select_read_format();

        let stride = (read_width as usize) * 4;
        let length = stride
            .checked_mul(read_height as usize)
            .context("DMA-BUF readback size overflowed")?;
        let mut data = vec![0u8; length];
        // SAFETY: `data` holds exactly `width * height * 4` bytes, which is the
        // amount `glReadPixels` writes for an 8-bit four-component format with
        // a pack alignment of one.
        unsafe {
            (self.entrypoints.gl_read_pixels)(
                0,
                0,
                read_width as i32,
                read_height as i32,
                self.read_format,
                GL_UNSIGNED_BYTE,
                data.as_mut_ptr().cast::<c_void>(),
            );
            (self.entrypoints.gl_finish)();
        }
        // SAFETY: as above.
        let read_error = unsafe { (self.entrypoints.gl_get_error)() };
        if read_error != GL_NO_ERROR {
            bail!("glReadPixels failed with GL error {read_error:#x}");
        }
        Ok(Readback {
            data,
            stride,
            width: read_width,
            height: read_height,
            layout: self.layout,
        })
    }

    /// Points the reusable framebuffer at the imported texture.
    fn attach_source_framebuffer(&mut self) -> Result<()> {
        // SAFETY: the framebuffer and texture names are live in this context.
        unsafe {
            (self.entrypoints.gl_bind_framebuffer)(GL_FRAMEBUFFER, self.framebuffer);
            (self.entrypoints.gl_framebuffer_texture_2d)(
                GL_FRAMEBUFFER,
                GL_COLOR_ATTACHMENT0,
                GL_TEXTURE_2D,
                self.texture,
                0,
            );
        }
        // SAFETY: a framebuffer is bound.
        let status = unsafe { (self.entrypoints.gl_check_framebuffer_status)(GL_FRAMEBUFFER) };
        if status != GL_FRAMEBUFFER_COMPLETE {
            bail!("imported DMA-BUF is not renderable (framebuffer status {status:#x})");
        }
        Ok(())
    }

    /// Builds the scaling program on first use.
    ///
    /// Returns whether scaling is available. A driver that refuses it is
    /// recorded so the attempt is not repeated for every frame.
    fn ensure_scale_pass(&mut self) -> bool {
        if self.scale.is_some() {
            return true;
        }
        if self.scale_unavailable {
            return false;
        }
        // An escape hatch for a driver that accepts the pass and then renders
        // it wrongly, which no runtime check here could detect.
        if std::env::var_os("GLACIALCAST_DISABLE_GPU_SCALING").is_some() {
            self.scale_unavailable = true;
            debug!("GPU frame scaling disabled by GLACIALCAST_DISABLE_GPU_SCALING");
            return false;
        }
        let Some(gl) = self.entrypoints.scale.as_ref() else {
            self.scale_unavailable = true;
            debug!("the GL stack lacks the entry points needed to scale frames on the GPU");
            return false;
        };
        match ScalePass::build(gl) {
            Ok(pass) => {
                debug!("scaling frames on the GPU before readback");
                self.scale = Some(pass);
                true
            }
            Err(error) => {
                warn!(%error, "GPU frame scaling is unavailable; reading frames back full size");
                self.scale_unavailable = true;
                false
            }
        }
    }

    /// Renders the imported texture into the destination framebuffer.
    ///
    /// Leaves that framebuffer bound so the caller reads back from it.
    fn draw_scaled(&mut self, target_width: u32, target_height: u32) -> Result<()> {
        let gl = self
            .entrypoints
            .scale
            .as_ref()
            .context("the scaling entry points went missing")?;
        let pass = self
            .scale
            .as_mut()
            .context("the scaling program went missing")?;

        if pass.size != (target_width, target_height) {
            // SAFETY: a context is current; names are generated on demand and
            // the old storage is replaced by this same call.
            unsafe {
                if pass.texture == 0 {
                    (self.entrypoints.gl_gen_textures)(1, &raw mut pass.texture);
                }
                if pass.framebuffer == 0 {
                    (self.entrypoints.gl_gen_framebuffers)(1, &raw mut pass.framebuffer);
                }
                if pass.texture == 0 || pass.framebuffer == 0 {
                    bail!("the driver returned no destination texture or framebuffer");
                }
                (self.entrypoints.gl_bind_texture)(GL_TEXTURE_2D, pass.texture);
                (gl.gl_tex_image_2d)(
                    GL_TEXTURE_2D,
                    0,
                    GL_RGBA as i32,
                    target_width as i32,
                    target_height as i32,
                    0,
                    GL_RGBA,
                    GL_UNSIGNED_BYTE,
                    std::ptr::null(),
                );
                (self.entrypoints.gl_tex_parameteri)(
                    GL_TEXTURE_2D,
                    GL_TEXTURE_MIN_FILTER,
                    GL_LINEAR,
                );
                (self.entrypoints.gl_tex_parameteri)(
                    GL_TEXTURE_2D,
                    GL_TEXTURE_MAG_FILTER,
                    GL_LINEAR,
                );
                (self.entrypoints.gl_tex_parameteri)(
                    GL_TEXTURE_2D,
                    GL_TEXTURE_WRAP_S,
                    GL_CLAMP_TO_EDGE,
                );
                (self.entrypoints.gl_tex_parameteri)(
                    GL_TEXTURE_2D,
                    GL_TEXTURE_WRAP_T,
                    GL_CLAMP_TO_EDGE,
                );
            }
            pass.size = (target_width, target_height);
        }

        // SAFETY: every name below is live in the current context, the vertex
        // array is four two-component floats matching the declared attribute,
        // and the source texture is bound to unit zero as the sampler expects.
        unsafe {
            (self.entrypoints.gl_bind_framebuffer)(GL_FRAMEBUFFER, pass.framebuffer);
            (self.entrypoints.gl_framebuffer_texture_2d)(
                GL_FRAMEBUFFER,
                GL_COLOR_ATTACHMENT0,
                GL_TEXTURE_2D,
                pass.texture,
                0,
            );
            let status = (self.entrypoints.gl_check_framebuffer_status)(GL_FRAMEBUFFER);
            if status != GL_FRAMEBUFFER_COMPLETE {
                bail!("the scaling framebuffer is incomplete (status {status:#x})");
            }

            (gl.gl_viewport)(0, 0, target_width as i32, target_height as i32);
            (gl.gl_use_program)(pass.program);
            (gl.gl_active_texture)(GL_TEXTURE0);
            (self.entrypoints.gl_bind_texture)(GL_TEXTURE_2D, self.texture);
            (gl.gl_uniform1i)(pass.sampler, 0);
            (gl.gl_enable_vertex_attrib_array)(pass.position);
            (gl.gl_vertex_attrib_pointer)(
                pass.position,
                2,
                GL_FLOAT,
                GL_FALSE_U8,
                0,
                SCALE_VERTICES.as_ptr().cast::<c_void>(),
            );
            (gl.gl_draw_arrays)(GL_TRIANGLE_STRIP, 0, 4);
        }
        // SAFETY: taking the current error code needs only a current context.
        let error = unsafe { (self.entrypoints.gl_get_error)() };
        if error != GL_NO_ERROR {
            bail!("the scaling draw failed with GL error {error:#x}");
        }
        Ok(())
    }

    /// Prefers the driver's native read format when it avoids a CPU swizzle.
    ///
    /// `GL_RGBA` with `GL_UNSIGNED_BYTE` is always accepted, so this only
    /// upgrades to `GL_BGRA_EXT` when the implementation reports it for the
    /// currently bound framebuffer.
    fn select_read_format(&mut self) {
        let mut format = 0;
        let mut kind = 0;
        // SAFETY: both queries write one `GLint` and a framebuffer is bound.
        unsafe {
            (self.entrypoints.gl_get_integerv)(GL_IMPLEMENTATION_COLOR_READ_FORMAT, &mut format);
            (self.entrypoints.gl_get_integerv)(GL_IMPLEMENTATION_COLOR_READ_TYPE, &mut kind);
        }
        if format as u32 == GL_BGRA_EXT && kind as u32 == GL_UNSIGNED_BYTE {
            self.read_format = GL_BGRA_EXT;
            self.layout = ReadbackLayout::Bgra;
        } else {
            self.read_format = GL_RGBA;
            self.layout = ReadbackLayout::Rgba;
        }
    }
}

impl Drop for EglReadback {
    fn drop(&mut self) {
        // SAFETY: every name was created by this context, which is still
        // current on this thread because the type cannot cross threads.
        unsafe {
            (self.entrypoints.gl_bind_framebuffer)(GL_FRAMEBUFFER, 0);
            (self.entrypoints.gl_delete_framebuffers)(1, &self.framebuffer);
            (self.entrypoints.gl_bind_texture)(GL_TEXTURE_2D, 0);
            (self.entrypoints.gl_delete_textures)(1, &self.texture);
            (self.entrypoints.egl_make_current)(
                self.display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            (self.entrypoints.egl_destroy_context)(self.display, self.context);
        }
    }
}

/// Releases an `EGLImage` when the readback finishes or fails.
struct EglImageGuard {
    display: *mut c_void,
    image: *mut c_void,
    destroy: EglDestroyImage,
}

impl Drop for EglImageGuard {
    fn drop(&mut self) {
        // SAFETY: `image` was created from `display` and has not been destroyed.
        unsafe {
            (self.destroy)(self.display, self.image);
        }
    }
}

/// The DRM sentinel meaning "the producer did not describe its tiling".
const DRM_FORMAT_MOD_INVALID: u64 = 0x00FF_FFFF_FFFF_FFFF;

/// Reports whether `name` appears as a whole entry in a space-separated
/// EGL extension string.
fn has_extension(extensions: &str, name: &str) -> bool {
    extensions.split_whitespace().any(|entry| entry == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_matching_requires_whole_entries() {
        let extensions = "EGL_EXT_image_dma_buf_import EGL_KHR_surfaceless_context";
        assert!(has_extension(extensions, "EGL_EXT_image_dma_buf_import"));
        assert!(has_extension(extensions, "EGL_KHR_surfaceless_context"));
        assert!(!has_extension(
            extensions,
            "EGL_EXT_image_dma_buf_import_modifiers"
        ));
        assert!(!has_extension(extensions, "EGL_KHR_surfaceless"));
    }

    #[test]
    fn invalid_modifier_sentinel_matches_drm() {
        // The DRM headers define DRM_FORMAT_MOD_INVALID as the vendor-NONE
        // modifier with all 56 payload bits set.
        assert_eq!(DRM_FORMAT_MOD_INVALID, (1u64 << 56) - 1);
    }
}
