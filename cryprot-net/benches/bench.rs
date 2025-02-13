use std::time::Instant;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use cryprot_net::testing::{init_bench_tracing, local_conn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    join,
};

fn criterion_benchmark(c: &mut Criterion) {
    init_bench_tracing();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut server, _client) = rt.block_on(local_conn()).unwrap();
    c.bench_function("create byte sub stream", |b| {
        b.to_async(&rt).iter_batched(
            || server.sub_connection(),
            |mut server| async move {
                server.byte_stream().await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    let (mut server, mut client) = rt.block_on(local_conn()).unwrap();

    c.bench_function("byte ping pong", |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let mut server = server.sub_connection();
            let mut client = client.sub_connection();
            async move {
                let (mut snd_s, mut rcv_s) = server.byte_stream().await.unwrap();
                let (mut snd_c, mut rcv_c) = client.byte_stream().await.unwrap();
                let now = Instant::now();

                for _ in 0..iters {
                    join!(
                        async {
                            snd_s.write_all(b"hello").await.unwrap();
                        },
                        async {
                            snd_c.write_all(b"hello").await.unwrap();
                        }
                    );
                    join!(
                        async {
                            let mut buf = [0; 5];
                            rcv_s.read_exact(&mut buf).await.unwrap();
                        },
                        async {
                            let mut buf = [0; 5];
                            rcv_c.read_exact(&mut buf).await.unwrap();
                        }
                    );
                }
                now.elapsed()
            }
        })
    });

    const KB: usize = 1024;
    let len = KB * KB;
    let buf = vec![0x42_u8; len];
    let buf = &buf;
    let (mut server, mut client) = rt.block_on(local_conn()).unwrap();
    let mut g = c.benchmark_group("throughput");
    // times two because each party sends buf.len() each iteration
    g.throughput(Throughput::Bytes(buf.len() as u64 * 2));
    g.bench_function(
        BenchmarkId::new("bytes ping pong", format!("{} KiB", len / KB)),
        |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let mut server = server.sub_connection();
                let mut client = client.sub_connection();
                async move {
                    let (mut snd_s, mut rcv_s) = server.byte_stream().await.unwrap();
                    let (mut snd_c, mut rcv_c) = client.byte_stream().await.unwrap();
                    let mut ret_buf_s = vec![0; len];
                    let mut ret_buf_c = vec![0; len];

                    let mut buf1 = buf.clone();
                    let mut buf2 = buf.clone();
                    let now = Instant::now();
                    for _ in 0..iters {
                        // some move shenanigans necessary to use tokio::spawn (requiring 'static),
                        // but not cloning all the time
                        let t1 = tokio::spawn(async move {
                            snd_s.write_all(&buf1).await.unwrap();
                            (snd_s, buf1)
                        });
                        let t2 = tokio::spawn(async move {
                            snd_c.write_all(&buf2).await.unwrap();
                            (snd_c, buf2)
                        });
                        let t3 = tokio::spawn(async move {
                            rcv_s.read_exact(&mut ret_buf_s).await.unwrap();
                            (rcv_s, ret_buf_s)
                        });
                        let t4 = tokio::spawn(async move {
                            rcv_c.read_exact(&mut ret_buf_c).await.unwrap();
                            (rcv_c, ret_buf_c)
                        });

                        let (r1, r2, r3, r4) = join!(t1, t2, t3, t4);
                        (snd_s, buf1) = r1.unwrap();
                        (snd_c, buf2) = r2.unwrap();
                        (rcv_s, ret_buf_s) = r3.unwrap();
                        (rcv_c, ret_buf_c) = r4.unwrap();
                    }
                    now.elapsed()
                }
            })
        },
    );

    let len = 10 * KB * KB;
    let buf = vec![0x42_u8; len];
    let buf = &buf;
    let (mut server, mut client) = rt.block_on(local_conn()).unwrap();
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function(
        BenchmarkId::new("one way", format!("{} MiB", len / KB / KB)),
        |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let mut server = server.sub_connection();
                let mut client = client.sub_connection();
                async move {
                    let (mut snd_s, _rcv_s) = server.byte_stream().await.unwrap();
                    let (_snd_c, mut rcv_c) = client.byte_stream().await.unwrap();
                    let mut ret_buf_c = vec![0; len];

                    let mut buf1 = buf.clone();
                    let now = Instant::now();
                    for _ in 0..iters {
                        // some move shenanigans necessary to use tokio::spawn (requiring 'static),
                        // but not cloning all the time
                        let t1 = tokio::spawn(async move {
                            snd_s.write_all(&buf1).await.unwrap();
                            (snd_s, buf1)
                        });
                        let t2 = tokio::spawn(async move {
                            rcv_c.read_exact(&mut ret_buf_c).await.unwrap();
                            (rcv_c, ret_buf_c)
                        });

                        let (r1, r2) = join!(t1, t2);
                        (snd_s, buf1) = r1.unwrap();
                        (rcv_c, ret_buf_c) = r2.unwrap();
                    }
                    now.elapsed()
                }
            })
        },
    );

    let (mut server, mut client) = rt.block_on(local_conn()).unwrap();
    g.throughput(Throughput::Bytes(buf.len() as u64 * 2));
    g.bench_function(
        BenchmarkId::new("one way parallel", format!("{} MiB", len / KB / KB)),
        |b| {
            b.to_async(&rt).iter_custom(|iters| {
                let mut server = server.sub_connection();
                let mut client = client.sub_connection();
                async move {
                    let (mut snd_s1, _rcv_s) = server.byte_stream().await.unwrap();
                    let (_snd_c, mut rcv_c1) = client.byte_stream().await.unwrap();
                    let (mut snd_s2, _rcv_s) = server.byte_stream().await.unwrap();
                    let (_snd_c, mut rcv_c2) = client.byte_stream().await.unwrap();

                    let mut ret_buf_c1 = vec![0; len];
                    let mut ret_buf_c2 = vec![0; len];

                    let mut buf1 = buf.clone();
                    let mut buf2 = buf.clone();
                    let now = Instant::now();
                    for _ in 0..iters {
                        // some move shenanigans necessary to use tokio::spawn (requiring 'static),
                        // but not cloning all the time
                        let t1 = tokio::spawn(async move {
                            snd_s1.write_all(&buf1).await.unwrap();
                            (snd_s1, buf1)
                        });
                        let t2 = tokio::spawn(async move {
                            snd_s2.write_all(&buf2).await.unwrap();
                            (snd_s2, buf2)
                        });
                        let t3 = tokio::spawn(async move {
                            rcv_c1.read_exact(&mut ret_buf_c1).await.unwrap();
                            (rcv_c1, ret_buf_c1)
                        });
                        let t4 = tokio::spawn(async move {
                            rcv_c2.read_exact(&mut ret_buf_c2).await.unwrap();
                            (rcv_c2, ret_buf_c2)
                        });

                        let (r1, r2, r3, r4) = join!(t1, t2, t3, t4);
                        (snd_s1, buf1) = r1.unwrap();
                        (snd_s2, buf2) = r2.unwrap();
                        (rcv_c1, ret_buf_c1) = r3.unwrap();
                        (rcv_c2, ret_buf_c2) = r4.unwrap();
                    }
                    now.elapsed()
                }
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
