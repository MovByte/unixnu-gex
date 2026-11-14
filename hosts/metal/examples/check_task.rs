//! The GPU Worker checked from where a process's kernel stands: a Worker
//! with an endpoint of the ring and a process memory, sending what the
//! kernel sends (`tests/page`, run by `tests/check_page.py`).
//!
//! The process memory maps its guest addresses above 4 GiB (as a Darwin
//! process's are) to offsets of the memory through its mapping table, so
//! every executor access is translated and checked as the kernel's
//! `TaskMemory` checks it. The checks:
//!
//! - the reference cases `compute.thread-positions` and
//!   `compute.indirect-dispatch` (WebMetal `tests/reference`), through the
//!   GPU Worker's own pipeline service (AirWgsl): requests, command
//!   buffers committed from guest memory, completion through the queue's
//!   doorbell and FetchEvents, results written into guest memory, compared
//!   with the reference outputs exactly;
//! - a blit fill and copy, and accesses the mapping table refuses (an
//!   unmapped stream, a read-only destination);
//! - an IOSurface handed to the GPU, read by a blit, written by a blit and
//!   read back as the kernel takes it back;
//! - frames presented on the canvas and read back from it: `BGRA` byte for
//!   byte, `b3a8` as the exact halves of its codes; frames the page cannot
//!   show refused with their reason; the panel's power.

#[cfg(target_arch = "wasm32")]
mod task {
    use std::collections::BTreeSet;

    use gex_metal_page::display::{self, fourcc};
    use gex_metal_page::memory::{EXEC, READ, WRITE};
    use gex_metal_page::protocol::{self, Frame, Layer, Plane, Reader, Rect, SurfaceDesc, Writer};
    use wasm_bindgen::prelude::*;
    use webmetal_host::exec::schema::{command_handles, reply_failure, Role};
    use webmetal_host::pipeline::sha256::sha256;
    use webmetal_wire::*;

    #[wasm_bindgen(module = "/js/task.js")]
    extern "C" {
        fn ep_send(kind: u32, b: u32, payload: &[u8]);
        fn ep_receive(kind: u32, ms: f64) -> Option<Vec<u8>>;
        fn ep_last_b() -> u32;
        fn ep_id() -> u32;
        fn ep_pending(kind: u32) -> u32;
        fn mem_write(offset: f64, bytes: &[u8]);
        fn mem_read(offset: f64, len: u32) -> Vec<u8>;
        fn table_set(words: &[u32]);
        fn fetch_bytes(path: &str) -> Option<Vec<u8>>;
        fn log(s: &str);
        fn result(name: &str, ok: bool, detail: &str);
    }

    /// The guest's read-write mapping: its addresses, and where they are in
    /// the memory.
    const GUEST: u64 = 0x1_2000_0000;
    const GUEST_AT: u64 = 0x10_0000;
    const GUEST_LEN: u64 = 48 << 20;
    /// A read-only mapping, an executable one, and an address nothing maps.
    const RO: u64 = 0x1_6000_0000;
    const RO_AT: u64 = 0x310_0000;
    const RX: u64 = 0x1_7000_0000;
    const RX_AT: u64 = 0x320_0000;
    const UNMAPPED: u64 = 0x1_8000_0000;
    const CONN: u64 = 1;
    const WAIT_MS: f64 = 120_000.0;

    fn table() -> Vec<u32> {
        let mut w = vec![0u32, 3, 0, 0];
        for (start, len, prot, at) in [(GUEST, GUEST_LEN, READ | WRITE, GUEST_AT), (RO, 1 << 20, READ, RO_AT), (RX, 1 << 20, READ | EXEC, RX_AT)] {
            let end = start + len;
            w.extend([start as u32, (start >> 32) as u32, end as u32, (end >> 32) as u32, prot, at as u32, (at >> 32) as u32, 0]);
        }
        w
    }

    fn offset(va: u64) -> f64 {
        for (start, len, at) in [(GUEST, GUEST_LEN, GUEST_AT), (RO, 1 << 20, RO_AT), (RX, 1 << 20, RX_AT)] {
            if va >= start && va < start + len {
                return (va - start + at) as f64;
            }
        }
        panic!("{va:#x} is not mapped");
    }

    struct Client {
        handles: u64,
        tokens: u64,
        cursor: u64,
        queue: Option<Handle>,
    }

    impl Client {
        fn handle(&mut self) -> Handle {
            self.handles += 1;
            Handle::new(self.handles).unwrap()
        }

        fn alloc(&mut self, len: u64) -> u64 {
            let a = self.cursor;
            self.cursor = (a + len).next_multiple_of(0x4000) + 0x4000;
            assert!(self.cursor < GUEST + GUEST_LEN, "the test's guest memory is used up");
            a
        }

        fn write(&self, va: u64, bytes: &[u8]) {
            mem_write(offset(va), bytes);
        }

        fn read(&self, va: u64, len: usize) -> Vec<u8> {
            mem_read(offset(va), len as u32)
        }

        /// A control request, as the kernel's `control` hands it over: the
        /// reply record, or the refusal.
        fn control(&mut self, r: &Request) -> Result<Reply, String> {
            let mut bytes = Vec::new();
            r.encode(&mut bytes).map_err(|e| format!("{e:?}"))?;
            self.tokens += 1;
            let token = self.tokens;
            let mut w = Writer::default();
            w.u64(CONN).u64(token).bytes(&bytes);
            ep_send(protocol::CONTROL, 0, &w.0);
            let p = ep_receive(protocol::REPLY, WAIT_MS).ok_or("no reply")?;
            let mut rd = Reader::new(&p, "a reply");
            let (t, outcome, _) = (rd.u64().unwrap(), rd.u32().unwrap(), rd.u32().unwrap());
            assert_eq!(t, token, "replies come in order");
            let rest = rd.rest();
            if outcome != 0 {
                return Err(format!("refused: {}", String::from_utf8_lossy(rest)));
            }
            Reply::decode(rest, 0).map(|(r, _)| r).map_err(|e| format!("{e:?}"))
        }

        fn status(&mut self, r: Request) -> Failure {
            match self.control(&r) {
                Ok(reply) => reply_failure(&reply).cloned().unwrap_or(Failure { status: 0, domain: None, code: 0, message: String::new() }),
                Err(e) => panic!("{e}"),
            }
        }

        fn ok(&mut self, r: Request) {
            let f = self.status(r);
            assert_eq!(f.status, status::OK, "{f:?}");
        }

        fn queue(&mut self) -> Handle {
            if let Some(q) = self.queue {
                return q;
            }
            let q = self.handle();
            self.ok(Request::CreateCommandQueue(CreateCommandQueue { queue: q }));
            self.queue = Some(q);
            q
        }

        fn buffer_with(&mut self, bytes: &[u8]) -> (Handle, u64) {
            let addr = self.alloc(bytes.len() as u64);
            self.write(addr, bytes);
            let b = self.handle();
            self.ok(Request::CreateBuffer(CreateBuffer { buffer: b, length: bytes.len() as u64, options: 0, contents: GuestAddr(addr) }));
            (b, addr)
        }

        /// Commit `records` from guest memory at `stream` (or a fresh range)
        /// and wait for the completion through the queue's doorbell and
        /// FetchEvents: its failure and failed offset.
        fn run_at(&mut self, records: &[Command], stream: Option<u64>) -> (Failure, u64) {
            let mut bytes = Vec::new();
            for r in records {
                r.encode(&mut bytes).unwrap();
            }
            let mut created = BTreeSet::new();
            let mut named = Vec::new();
            for r in records {
                command_handles(r, &mut |u| {
                    if u.role == Role::Result {
                        created.insert(u.handle);
                    } else if !named.contains(&u.handle) {
                        named.push(u.handle);
                    }
                });
            }
            named.retain(|h| !created.contains(h));
            let addr = match stream {
                Some(a) => a,
                None => {
                    let a = self.alloc(bytes.len() as u64);
                    self.write(a, &bytes);
                    a
                }
            };
            let queue = self.queue();
            let cb = self.handle();
            let f = self.status(Request::Commit(Commit {
                command_buffer: cb,
                queue,
                label: None,
                retained_references: true,
                error_options: 0,
                stream: GuestAddr(addr),
                stream_length: bytes.len() as u64,
                resources: named,
            }));
            if f.status != status::OK {
                return (f, u64::MAX);
            }
            loop {
                let ring = ep_receive(protocol::RING, WAIT_MS).expect("the queue's doorbell");
                let mut rd = Reader::new(&ring, "a doorbell");
                let (conn, q) = (rd.u64().unwrap(), rd.u64().unwrap());
                assert_eq!((conn, q), (CONN, queue.0.get()), "the doorbell of the connection's queue");
                let Ok(Reply::FetchEvents(Ok(r))) = self.control(&Request::FetchEvents(FetchEvents { queue: Some(queue) })) else {
                    panic!("FetchEvents failed");
                };
                for (_, e) in Event::decode_all(&r.events).unwrap() {
                    if let Event::CommandBufferCompleted(c) = e {
                        if c.command_buffer == cb {
                            return (c.failure, c.failed_offset);
                        }
                    }
                }
            }
        }

        fn run(&mut self, records: Vec<Command>) {
            let (f, at) = self.run_at(&records, None);
            assert_eq!(f.status, status::OK, "offset {at}: {f:?}");
        }

        fn encoder(&mut self, begin: fn(Handle) -> Command, body: Vec<Command>) -> Vec<Command> {
            let e = self.handle();
            let mut v = vec![begin(e)];
            v.extend(body);
            v.push(Command::EncoderEndEncoding(EncoderEndEncoding {}));
            v
        }

        /// A compute pipeline of a reference kernel.
        fn pipeline(&mut self, bitcode: &[u8], name: &str) -> Handle {
            let hash = sha256(bitcode);
            self.ok(Request::RegisterAir(RegisterAir { hash: Hash { bytes: hash }, bitcode: bitcode.to_vec() }));
            let f = self.handle();
            self.ok(Request::RegisterFunction(RegisterFunction { function: f, air: Hash { bytes: hash }, name: name.into(), function_type: 3, constants: Vec::new() }));
            let p = self.handle();
            self.ok(Request::CreateComputePipeline(CreateComputePipeline { pipeline: p, descriptor: compute_descriptor(f), options: 0, reflection: false, error: false }));
            p
        }
    }

    fn compute_descriptor(function: Handle) -> ComputePipelineDescriptor {
        ComputePipelineDescriptor {
            binary_archives: Vec::new(),
            binary_libraries: Vec::new(),
            buffers: Vec::new(),
            compute_function: Some(function),
            driver_compiler_options: None,
            dynamic_libraries: Vec::new(),
            force_resource_index: false,
            function_pointers: Vec::new(),
            gpu_compiler_spi_options: None,
            insert_libraries: Vec::new(),
            label: None,
            linked_functions: None,
            max_acceleration_structure_traversal_depth: 0,
            max_call_stack_depth: 1,
            max_total_threads_per_threadgroup: 0,
            needs_custom_border_color_samplers: false,
            open_cl_mode_enabled: false,
            open_gl_mode_enabled: false,
            pipeline_library: false,
            plugin_data: None,
            preloaded_libraries: Vec::new(),
            profile_control: None,
            resource_index: 0,
            stage_input_descriptor: None,
            support_adding_binary_functions: false,
            support_indirect_command_buffers: false,
            texture_write_fp_rounding_mode: 0,
            texture_write_rounding_mode: 0,
            thread_group_size_is_multiple_of_thread_execution_width: false,
        }
    }

    /// A shared 2D texture descriptor with Metal's defaults.
    fn texture_descriptor(format: u64, w: u64, h: u64, usage: u64) -> TextureDescriptor {
        TextureDescriptor {
            allow_gpu_optimized_contents: true,
            array_length: 1,
            color_space_conversion_matrix: 0,
            compression_footprint: 0,
            compression_mode: 0,
            compression_type: 0,
            cpu_cache_mode: 0,
            depth: 1,
            force_resource_index: false,
            framebuffer_only: false,
            hazard_tracking_mode: 0,
            height: h,
            is_drawable: false,
            lossy_compression_mode: 0,
            mipmap_level_count: 1,
            pixel_format: format,
            protection_options: 0,
            resource_index: 0,
            resource_options: 0,
            rotation: 0,
            sample_count: 1,
            sparse_surface_default_value: 0,
            storage_mode: 0,
            swizzle: TextureSwizzleChannels { red: 2, green: 3, blue: 4, alpha: 5 },
            swizzle_key: 0,
            texture_type: 2,
            texture_usage: usage,
            usage,
            width: w,
            write_swizzle_enabled: false,
        }
    }

    fn size(width: u64, height: u64, depth: u64) -> Size {
        Size { width, height, depth }
    }

    fn origin() -> Origin {
        Origin { x: 0, y: 0, z: 0 }
    }

    fn grid(x: u32, y: u32, z: u32) -> Vec<u8> {
        [x, y, z, 0].iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// The hex bytes of `data` record `name` of a reference case's file.
    fn golden(case: &str, name: &str) -> Vec<u8> {
        let path = format!("/__webmetal/tests/reference/goldens/apple-m4-macos-27.0.1-26a434/release/{case}.json");
        let text = String::from_utf8(fetch_bytes(&path).unwrap_or_else(|| panic!("{path} is not served"))).unwrap();
        let key = format!("\"name\":\"{name}\"");
        let line = text.lines().find(|l| l.contains(&key) && l.contains("\"kind\":\"data\"")).unwrap_or_else(|| panic!("{case}: no {name}"));
        assert!(line.contains("\"compare\":\"exact\""), "{case}: {name} is not an exact record");
        let at = line.find("\"hex\":\"").unwrap() + 7;
        let hex = &line[at..at + line[at..].find('"').unwrap()];
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn library_function(name: &str) -> Vec<u8> {
        let data = fetch_bytes("/__reference/wmref.metallib").expect("the reference library is served");
        let lib = airwgsl::parse_metallib(&data).expect("a metallib");
        lib.functions.iter().find(|f| f.name == name).and_then(|f| f.module).unwrap_or_else(|| panic!("{name}")).to_vec()
    }

    thread_local! {
        static CURRENT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    }

    /// Run check `name`. A failing check panics, which aborts the module (its
    /// only panic strategy): the panic hook reports it, and the checks after
    /// it do not run.
    fn check(name: &str, f: impl FnOnce() -> String) {
        CURRENT.with(|c| *c.borrow_mut() = name.to_string());
        let detail = f();
        result(name, true, &detail);
    }

    fn compute_cases(c: &mut Client) -> String {
        let p = c.pipeline(&library_function("compute_positions"), "compute_positions");
        let (out, out_addr) = c.buffer_with(&vec![0; 12 * 4 * 2 * 64]);
        let body = vec![
            Command::ComputeSetComputePipelineState(ComputeSetComputePipelineState { state: Some(p) }),
            Command::ComputeSetBuffer(ComputeSetBuffer { buffer: Some(out), offset: 0, index: 0 }),
            Command::ComputeSetBytes(ComputeSetBytes { bytes: grid(12, 4, 2), length: 16, index: 1 }),
            Command::ComputeDispatchThreadgroups(ComputeDispatchThreadgroups { threadgroups_per_grid: size(3, 2, 2), threads_per_threadgroup: size(4, 2, 1) }),
        ];
        let v = c.encoder(|e| Command::BeginCompute(BeginCompute { encoder: e }), body);
        c.run(v);
        let got = c.read(out_addr, 12 * 4 * 2 * 64);
        assert_eq!(got, golden("compute.thread-positions", "records"), "compute.thread-positions");

        let (out, out_addr) = c.buffer_with(&vec![0; 6 * 3 * 64]);
        let args: Vec<u8> = [0xdead, 0xbeef, 0xfeed, 0xface, 3, 3, 1, 0u32].iter().flat_map(|v| v.to_le_bytes()).collect();
        let (indirect, _) = c.buffer_with(&args);
        let body = vec![
            Command::ComputeSetComputePipelineState(ComputeSetComputePipelineState { state: Some(p) }),
            Command::ComputeSetBuffer(ComputeSetBuffer { buffer: Some(out), offset: 0, index: 0 }),
            Command::ComputeSetBytes(ComputeSetBytes { bytes: grid(6, 3, 1), length: 16, index: 1 }),
            Command::ComputeDispatchThreadgroupsWithIndirectBuffer(ComputeDispatchThreadgroupsWithIndirectBuffer {
                indirect_buffer: Some(indirect),
                indirect_buffer_offset: 16,
                threads_per_threadgroup: size(2, 1, 1),
            }),
        ];
        let v = c.encoder(|e| Command::BeginCompute(BeginCompute { encoder: e }), body);
        c.run(v);
        assert_eq!(c.read(out_addr, 6 * 3 * 64), golden("compute.indirect-dispatch", "records"), "compute.indirect-dispatch");
        "compute.thread-positions and compute.indirect-dispatch: every record equal to the reference".into()
    }

    fn blit_cases(c: &mut Client) -> String {
        let src: Vec<u8> = (0..256u32).map(|i| (i * 7 + 3) as u8).collect();
        let (a, _) = c.buffer_with(&src);
        let (b, b_addr) = c.buffer_with(&vec![0x55; 256]);
        let v = c.encoder(
            |e| Command::BeginBlit(BeginBlit { encoder: e }),
            vec![
                Command::BlitFillBuffer(BlitFillBuffer { buffer: Some(b), range: Range { location: 16, length: 32 }, value: 0xa5 }),
                Command::BlitCopyBufferToBuffer(BlitCopyBufferToBuffer { source_buffer: Some(a), source_offset: 64, destination_buffer: Some(b), destination_offset: 128, size: 64 }),
            ],
        );
        c.run(v);
        let got = c.read(b_addr, 256);
        let mut want = vec![0x55u8; 256];
        want[16..48].fill(0xa5);
        want[128..192].copy_from_slice(&src[64..128]);
        assert_eq!(got, want, "fill and copy, written into guest memory");
        "fillBuffer and copyFromBuffer: guest memory as Metal leaves it".into()
    }

    fn fault_cases(c: &mut Client) -> String {
        // A command stream nothing maps.
        let records = c.encoder(|e| Command::BeginBlit(BeginBlit { encoder: e }), vec![]);
        let (f, _) = c.run_at(&records, Some(UNMAPPED));
        assert_ne!(f.status, status::OK, "a stream at an unmapped address: {f:?}");
        let unmapped = format!("unmapped stream: status {} ({})", f.status, f.message);
        // A buffer whose contents are read-only: creating it reads them; the
        // GPU's write into it must fail.
        let b = c.handle();
        let created = c.status(Request::CreateBuffer(CreateBuffer { buffer: b, length: 64, options: 0, contents: GuestAddr(RO) }));
        let ro = if created.status == status::OK {
            let v = c.encoder(
                |e| Command::BeginBlit(BeginBlit { encoder: e }),
                vec![Command::BlitFillBuffer(BlitFillBuffer { buffer: Some(b), range: Range { location: 0, length: 64 }, value: 1 })],
            );
            let (f, _) = c.run_at(&v, None);
            assert_ne!(f.status, status::OK, "a GPU write into a read-only mapping: {f:?}");
            assert_eq!(c.read(RO, 64), vec![0; 64], "the read-only mapping is unchanged");
            format!("write into a read-only mapping: status {} ({})", f.status, f.message)
        } else {
            format!("a buffer over a read-only mapping: status {} ({})", created.status, created.message)
        };
        format!("{unmapped}; {ro}")
    }

    fn surface_cases(c: &mut Client) -> String {
        const ID: u32 = 0x501;
        let (w, h) = (8u64, 4u64);
        let bpr = w * 4;
        let desc = SurfaceDesc {
            id: ID,
            width: w,
            height: h,
            bytes_per_row: bpr,
            bytes_per_element: 4,
            element_width: 1,
            element_height: 1,
            offset: 0,
            pixel_format: fourcc(b"BGRA"),
            alloc_size: bpr * h,
            planes: Vec::new(),
            seed: 0,
        };
        ep_send(protocol::SURFACE_BIND, 0, &desc.encode());
        let pattern: Vec<u8> = (0..(bpr * h) as u32).map(|i| (i * 13 + 1) as u8).collect();
        let mut wr = Writer::default();
        wr.u32(ID).u32(0);
        protocol::encode_runs(&mut wr, &[(0, &pattern)]);
        ep_send(protocol::SURFACE_CPU_WROTE, 0, &wr.0);
        let t = c.handle();
        c.ok(Request::CreateTextureWithIOSurface(CreateTextureWithIOSurface {
            texture: t,
            descriptor: texture_descriptor(80, w, h, 0x1),
            iosurface: SurfaceId(ID),
            plane: 0,
        }));
        let (out, out_addr) = c.buffer_with(&vec![0; (bpr * h) as usize]);
        let v = c.encoder(
            |e| Command::BeginBlit(BeginBlit { encoder: e }),
            vec![Command::BlitCopyTextureToBuffer(BlitCopyTextureToBuffer {
                source_texture: Some(t),
                source_slice: 0,
                source_level: 0,
                source_origin: origin(),
                source_size: size(w, h, 1),
                destination_buffer: Some(out),
                destination_offset: 0,
                destination_bytes_per_row: bpr,
                destination_bytes_per_image: bpr * h,
            })],
        );
        c.run(v);
        assert_eq!(c.read(out_addr, (bpr * h) as usize), pattern, "the surface's bytes, as the kernel handed them over");
        // The GPU writes the surface; the kernel takes the writes back.
        let new: Vec<u8> = (0..(bpr * h) as u32).map(|i| (i * 5 + 200) as u8).collect();
        let (src, _) = c.buffer_with(&new);
        let v = c.encoder(
            |e| Command::BeginBlit(BeginBlit { encoder: e }),
            vec![Command::BlitCopyBufferToTexture(BlitCopyBufferToTexture {
                source_buffer: Some(src),
                source_offset: 0,
                source_bytes_per_row: bpr,
                source_bytes_per_image: bpr * h,
                source_size: size(w, h, 1),
                destination_texture: Some(t),
                destination_slice: 0,
                destination_level: 0,
                destination_origin: origin(),
            })],
        );
        c.run(v);
        let mut wr = Writer::default();
        wr.u32(ID).u32(0).u64(77);
        ep_send(protocol::SURFACE_READ_BACK, 0, &wr.0);
        let p = ep_receive(protocol::READ_BACK, WAIT_MS).expect("READ_BACK");
        let mut rd = Reader::new(&p, "READ_BACK");
        assert_eq!(rd.u64().unwrap(), 77);
        let runs = protocol::decode_runs(&mut rd).unwrap();
        let mut store = pattern.clone();
        for (at, bytes) in &runs {
            store[*at as usize..*at as usize + bytes.len()].copy_from_slice(bytes);
        }
        assert_eq!(store, new, "the GPU's writes, taken back");
        let mut wr = Writer::default();
        wr.u32(ID).u32(0).u64(78);
        ep_send(protocol::SURFACE_READ_BACK, 0, &wr.0);
        let p = ep_receive(protocol::READ_BACK, WAIT_MS).expect("READ_BACK");
        let mut rd = Reader::new(&p, "READ_BACK");
        rd.u64().unwrap();
        assert!(protocol::decode_runs(&mut rd).unwrap().is_empty(), "taken once");
        let mut wr = Writer::default();
        wr.u32(ID);
        ep_send(protocol::SURFACE_RELEASED, 0, &wr.0);
        format!("IOSurface {ID:#x}: the kernel's bytes reach a blit; the GPU's write comes back in {} runs", runs.len())
    }

    fn plane(offset: u64, w: u64, h: u64, bpr: u64, bpe: u32) -> Plane {
        Plane { offset, width: w, height: h, bytes_per_row: bpr, bytes_per_element: bpe, element_width: 1, element_height: 1, size: bpr * h }
    }

    fn frame(swap: u32, panel: (u32, u32), layers: Vec<Layer>) -> Frame {
        Frame { swap_id: swap, vbl: u64::from(swap), time: 0, panel, layers }
    }

    fn full(w: u32, h: u32) -> Rect {
        Rect { x: 0, y: 0, w: w as i32, h: h as i32 }
    }

    /// Present `f`, asking for the canvas's bytes: `Ok(bytes)` or the refusal.
    fn present(f: &Frame) -> Result<Vec<u8>, String> {
        ep_send(protocol::PRESENT, 1, &f.encode());
        let p = ep_receive(protocol::PRESENTED, WAIT_MS).expect("PRESENTED");
        let mut rd = Reader::new(&p, "PRESENTED");
        let (swap, outcome) = (rd.u32().unwrap(), rd.u32().unwrap());
        assert_eq!(swap, f.swap_id);
        let rest = rd.rest().to_vec();
        if outcome != 0 {
            return Err(String::from_utf8_lossy(&rest).into_owned());
        }
        assert_eq!(ep_last_b(), 1, "a checked frame's answer carries the canvas's bytes");
        Ok(rest)
    }

    /// The canvas's rows (padded to 256 bytes) without their padding.
    fn rows(bytes: &[u8], w: usize, h: usize, texel: usize) -> Vec<u8> {
        let bpr = (w * texel).next_multiple_of(256);
        (0..h).flat_map(|y| bytes[y * bpr..y * bpr + w * texel].to_vec()).collect()
    }

    fn present_cases() -> String {
        let (w, h) = (64u32, 16u32);
        let n = (w * h) as usize;
        // BGRA: the canvas holds the bytes.
        let bgra: Vec<u8> = (0..n * 4).map(|i| ((i * 2654435761usize) >> 7) as u8).collect();
        let l = Layer { index: 0, surface: 1, pixel_format: fourcc(b"BGRA"), width: w.into(), height: h.into(), planes: vec![plane(0, w.into(), h.into(), (w * 4).into(), 4)], bytes: bgra.clone(), src: full(w, h), dst: full(w, h), transform: 0 };
        let got = present(&frame(1, (w, h), vec![l.clone()])).expect("a BGRA frame");
        assert_eq!(rows(&got, w as usize, h as usize, 4), bgra, "the canvas holds the BGRA frame's bytes");
        // b3a8: every 10-bit code in each channel, the halves of their values.
        let xr = display::xr_halves();
        let alpha = display::unorm8_halves();
        let mut bytes = vec![0u8; n * 4 + n];
        let mut want = Vec::with_capacity(n * 8);
        for i in 0..n {
            let (r, g, b, a) = (i as u32, 1023 - i as u32, (i as u32 * 7) % 1024, (i % 256) as u8);
            let v = (3 << 30) | (r << 20) | (g << 10) | b;
            bytes[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
            bytes[n * 4 + i] = a;
            for x in [xr[r as usize], xr[g as usize], xr[b as usize], alpha[a as usize]] {
                want.extend_from_slice(&x.to_le_bytes());
            }
        }
        let l3 = Layer {
            index: 0,
            surface: 2,
            pixel_format: fourcc(b"b3a8"),
            width: w.into(),
            height: h.into(),
            planes: vec![plane(0, w.into(), h.into(), (w * 4).into(), 4), plane((n * 4) as u64, w.into(), h.into(), w.into(), 1)],
            bytes,
            src: full(w, h),
            dst: full(w, h),
            transform: 0,
        };
        let got = present(&frame(2, (w, h), vec![l3])).expect("a b3a8 frame");
        assert_eq!(rows(&got, w as usize, h as usize, 8), want, "the canvas holds each code's half");
        // Refused frames.
        let mut argb = l.clone();
        argb.pixel_format = fourcc(b"ARGB");
        let e = present(&frame(3, (w, h), vec![argb])).unwrap_err();
        assert!(e.contains("no description"), "{e}");
        let e = present(&frame(4, (w, h), vec![l.clone(), l.clone()])).unwrap_err();
        assert!(e.contains("blending"), "{e}");
        let mut scaled = l.clone();
        scaled.dst = full(w / 2, h);
        let e = present(&frame(5, (w, h), vec![scaled])).unwrap_err();
        assert!(e.contains("covers the panel"), "{e}");
        // The panel's power.
        for on in [0u32, 1] {
            let mut wr = Writer::default();
            wr.u32(on);
            ep_send(protocol::PANEL, 0, &wr.0);
            let p = ep_receive(protocol::PANEL_DONE, WAIT_MS).expect("PANEL_DONE");
            assert_eq!(u32::from_le_bytes(p[0..4].try_into().unwrap()), 0, "{}", String::from_utf8_lossy(&p[8..]));
        }
        format!("BGRA {w}x{h} byte for byte; b3a8 {w}x{h} ({n} codes per channel) as the exact halves; ARGB, two layers and a scaled layer refused")
    }

    /// Run the checks; each result goes to the page.
    #[wasm_bindgen]
    pub fn run_checks() {
        std::panic::set_hook(Box::new(|info| {
            let name = CURRENT.with(|c| c.borrow().clone());
            result(&name, false, &info.to_string());
        }));
        table_set(&table());
        let mut w = Writer::default();
        w.u64(CONN).i32(1).u32(1);
        ep_send(protocol::OPEN, 0, &w.0);
        let mut c = Client { handles: 0x100, tokens: 0, cursor: GUEST + 0x1000, queue: None };
        check("open", || {
            c.ok(Request::Open(Open { schema_hash: Hash { bytes: SCHEMA_HASH }, pid: 1 }));
            format!("endpoint {}", ep_id())
        });
        check("compute", || compute_cases(&mut c));
        check("blit", || blit_cases(&mut c));
        check("faults", || fault_cases(&mut c));
        check("iosurface", || surface_cases(&mut c));
        check("present", present_cases);
        let reports = ep_pending(protocol::REPORT);
        let mut texts = Vec::new();
        for _ in 0..reports {
            let p = ep_receive(protocol::REPORT, 0.0).unwrap();
            texts.push(String::from_utf8_lossy(&p[8..]).into_owned());
        }
        result("reports", true, &texts.join(" | "));
        let mut w = Writer::default();
        w.u64(CONN);
        ep_send(protocol::CLOSE, 0, &w.0);
    }
}
