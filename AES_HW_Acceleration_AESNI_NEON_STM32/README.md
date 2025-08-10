# Description

This project implements AES-128 using hardware-assisted instructions on PCs (Intel/AMD AES-NI, ARM NEON/crypto) with both pre-expanded keys and on-the-fly key expansion, written in C/C++ intrinsics without loops or non-inline calls. It includes a benchmarking suite to measure and compare runtimes under identical conditions, plus two STM32 Nucleo-F030R8 firmware variants (straightforward and T-box optimized) with UART logging and HAL-based timing to contrast PC vs. microcontroller performance.
