# Plan: Developing a C++ Static Library for Detecting Potential File Encryption

## 1. Objective

The primary objective is to develop C++ libraries:
  - static (`.a`)
  - dynamic (`.dylib`)
This library format facilitates easy integration into various C++ projects, such as tools for analyzing game assets or general file system utilities, without requiring repeated compilation.

The library's core functionality will be to provide a heuristic assessment of whether a given file is likely encrypted using a strong algorithm like AES. This analysis will be performed solely based on the file's byte-level statistical properties, without access to any decryption keys or prior knowledge of specific file formats. The goal is to offer a preliminary check: does the file content resemble random noise or structured data?

## 2. Core Principle: Statistical Randomness

The fundamental principle leverages the observation that data encrypted with robust algorithms (like AES) exhibits characteristics closely approximating a uniform random distribution of byte values. Each byte value (0-255) should occur with roughly equal probability, resulting in high *Shannon entropy*. This statistical profile contrasts sharply with typical unencrypted data.

Consider these examples:
*   **Text files** (`.txt`, `.cpp`, `.h`, etc.): Show strong biases towards common characters (e.g., space, 'e', 'a', 't' in English), specific line endings, and recurring keywords or syntax patterns.
*   **Executables** (e.g., Linux ELF binaries, macOS Mach-O applications): Contain defined structures like headers, distinct code and data sections, and relocation tables, all of which deviate significantly from randomness.
*   **Shared Libraries** (`.so` on Linux, `.dylib` on macOS): Exhibit similar structured, non-random characteristics as executables.
*   **Media Files** (Images, Audio, Video): Even complex media files possess internal structures, headers, metadata, and often contain repeating patterns or correlations, especially if uncompressed or losslessly compressed.

Therefore, the library will function by quantifying the degree of statistical randomness within a file's byte stream. A high degree of randomness suggests potential encryption or effective compression. Distinguishing between these two possibilities based purely on these statistical measures is inherently challenging and considered outside the scope of this initial library.

## 3. Proposed Methodology: Statistical Analysis of Byte Frequency Distribution

This section details the proposed algorithm for heuristically identifying potentially encrypted files based on statistical analysis. The core premise is that well-encrypted data should approximate a uniformly random distribution of byte values, exhibiting maximum entropy, whereas unencrypted data (text, executables, structured formats) typically displays significant deviation from uniformity.

*   **Input:** The algorithm accepts a single parameter: the file path (`std::string`) to the target file for analysis.

*   **Procedure:** The analysis proceeds in the following stages:
    1.  **File Ingestion and Byte Frequency Aggregation:**
        *   The file specified by the input path would be opened in binary input mode (`std::ios::binary`). This is crucial to ensure byte integrity, preventing any platform-specific data transformations (e.g., line ending conversions) that could corrupt the byte frequency data essential for subsequent statistical analysis.
        *   The initial bytes of the file **would be** read first for the header check. If no known header is found, the process continues by reading the rest of the file sequentially (or a sufficiently large prefix) for frequency counting. This avoids excessive memory allocation for large files.
        *   Error handling would be incorporated for file I/O operations.
        *   A frequency array, `std::vector<unsigned long long> counts(256, 0)`, would be used to store the occurrence count for each possible byte value (0-255) *if* the statistical analysis proceeds.
        *   Byte frequencies **would be** aggregated during the sequential read phase.

    2.  **Preliminary Header Check (Magic Number Scan):**
        *   *Rationale:* Before performing computationally more intensive statistical analysis, a quick check of the file's initial bytes against known signatures (magic numbers) for common non-encrypted, potentially high-entropy file types (especially compressed archives and media formats) can efficiently identify many files that are not the target of the encryption detection.
        *   *Implementation:* The first N bytes of the file (where N is sufficient to cover common signatures, e.g., 8-16 bytes) **would be** compared against a predefined list of known magic numbers. Examples include:
            *   ZIP: `50 4B 03 04` (`PK..`)
            *   Gzip: `1F 8B 08`
            *   Bzip2: `42 5A 68` (`BZh`)
            *   PNG: `89 50 4E 47 0D 0A 1A 0A` (`.PNG....`)
            *   JPEG: `FF D8 FF`
            *   PDF: `25 50 44 46` (`%PDF`)
            *   (Others as deemed necessary: RAR, 7z, various media formats)
        *   *Outcome:* If a known signature is matched, the analysis **could** conclude early, potentially returning a specific result like `KNOWN_FILE_TYPE` or `LIKELY_COMPRESSED`, distinct from the results of the statistical tests.

    3.  **Statistical Measure Calculation (Conditional):** If the preliminary header check does not identify a known file type, *then* the aggregated `counts` data **would be** subjected to the following statistical tests:

        *   **A) Shannon Entropy Calculation:**
            *   *Theoretical Basis:* Shannon entropy, denoted \( H \), quantifies the average information content or uncertainty associated with a random variable. For a discrete random variable \( X \) with possible outcomes \( x_1, ..., x_k \) and probabilities \( P(x_i) \), the entropy is defined as: \[ H(X) = - \sum_{i=1}^{k} P(x_i) \log_b P(x_i) \] In this context, the random variable represents a byte read from the file, with 256 possible outcomes (byte values 0-255). The probability \( p_i \) of observing byte value \( i \) is estimated from the frequency data as \( p_i = \frac{\text{counts}[i]}{\text{total\_bytes}} \). The base of the logarithm \( b \) is typically chosen as 2, resulting in entropy measured in bits.
            *   *Application:* A perfectly uniform distribution of byte values (characteristic of ideal random data, approximated by strong encryption or compression) yields the maximum possible entropy for an 8-bit variable: \( H_{max} = \log_2(256) = 8 \) bits per byte. Conversely, data with repetitive patterns or skewed distributions will exhibit lower entropy.
            *   *Implementation:* The calculation **would** first determine `total_bytes` from the sum of `counts`. If `total_bytes` is zero, entropy is defined as 0. Otherwise, the formula \( H = - \sum_{i=0}^{255} \frac{\text{counts}[i]}{\text{total\_bytes}} \log_2 \left( \frac{\text{counts}[i]}{\text{total\_bytes}} \right) \) **would be** computed, skipping terms where `counts[i]` is zero (as \( \lim_{p \to 0} p \log_2 p = 0 \)).
            *   *Interpretation:* An entropy value approaching 8.0 strongly suggests high randomness, consistent with encryption or compression. Values significantly lower than 8.0 indicate non-random structure.
            *   *Conceptual C++ Snippet:*
                ```cpp
                #include <vector>
                #include <cmath>
                #include <numeric>

                double calculate_shannon_entropy(const std::vector<unsigned long long>& counts) {
                    unsigned long long total_bytes = std::accumulate(counts.begin(), counts.end(), 0ULL);
                    if (total_bytes == 0) return 0.0;
                    double entropy = 0.0;
                    double log2_total_bytes = std::log2(static_cast<double>(total_bytes));
                    for (unsigned long long count : counts) {
                        if (count > 0) {
                            double p_i = static_cast<double>(count) / total_bytes;
                            // Use log property: log2(count/total) = log2(count) - log2(total)
                            // entropy -= p_i * std::log2(p_i); becomes:
                            entropy -= p_i * (std::log2(static_cast<double>(count)) - log2_total_bytes);
                        }
                    }
                    return entropy;
                }
                ```

        *   **B) Pearson's Chi-Squared (χ²) Goodness-of-Fit Test:**
            *   *Theoretical Basis:* The Chi-squared test is employed to determine if there is a significant difference between the observed frequencies (our byte `counts`) and the frequencies expected under a specific theoretical distribution (the null hypothesis, H₀). Here, H₀ is that the bytes are drawn from a discrete uniform distribution.
            *   *Null Hypothesis (H₀):* The observed byte frequencies are consistent with a uniform distribution (i.e., \( P(\text{byte}=i) = 1/256 \) for all \( i \in [0, 255] \)).
            *   *Alternative Hypothesis (H₁):* The observed byte frequencies are *not* consistent with a uniform distribution.
            *   *Test Statistic Calculation:* The χ² statistic is calculated as: \[ \chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i} \] where \( O_i = \text{counts}[i] \) is the observed frequency for byte value \( i \), and \( E_i = \frac{\text{total\_bytes}}{256} \) is the expected frequency for each byte value under H₀.
            *   *Degrees of Freedom:* The number of degrees of freedom (df) for this test is \( k - 1 = 256 - 1 = 255 \), where \( k \) is the number of categories (byte values).
            *   *Implementation:* The calculation **would** first determine `total_bytes` and the `expected_count_per_byte = static_cast<double>(total_bytes) / 256.0`. Care must be taken to handle the case where `expected_count_per_byte` is zero (if `total_bytes < 256`), although this scenario should ideally be precluded by a minimum file size check. The sum defining the χ² statistic **would then be** computed.
            *   *Interpretation:* A small χ² value indicates that the observed frequencies are close to the expected uniform frequencies, providing evidence *against* rejecting H₀. A large χ² value indicates a significant deviation from uniformity, providing evidence *for* rejecting H₀ (and concluding the data is likely not uniformly random). The significance of the statistic is typically assessed by comparing it to a critical value from the χ² distribution with 255 df at a chosen significance level (e.g., α = 0.05), or by calculating the p-value.
            *   *Proposed Simplification:* Calculating the exact p-value for χ² with 255 df typically requires specialized mathematical functions (related to the incomplete gamma function). For this initial implementation, **it is proposed** to compare the calculated `chi_squared_statistic` against the pre-determined critical value for α = 0.05 and df = 255 (approximately 293.248). If `statistic <= critical_value`, the result is consistent with H₀ (uniformity/randomness). If `statistic > critical_value`, H₀ is rejected (likely not uniform/random). This provides a practical decision boundary without requiring a complex p-value calculation library.
            *   *Conceptual C++ Snippet:*
                ```cpp
                #include <vector>
                #include <cmath>
                #include <numeric>
                #include <limits> // Required for infinity()

                const double CHI_SQUARED_CRITICAL_VALUE_DF255_P05 = 293.2478;

                double calculate_chi_squared(const std::vector<unsigned long long>& counts) {
                    unsigned long long total_bytes = std::accumulate(counts.begin(), counts.end(), 0ULL);
                    // Chi-squared test requires sufficient expected counts per bin.
                    // A common rule of thumb is expected count >= 5.
                    // With 256 bins, this implies total_bytes >= 5 * 256 = 1280.
                    // We use total_bytes < 256 as a simpler preliminary check here, but
                    // a higher threshold might be more statistically sound.
                    if (total_bytes < 256) return std::numeric_limits<double>::infinity(); // Indicate test is not valid

                    double expected_count_per_byte = static_cast<double>(total_bytes) / 256.0;
                    double chi_squared_statistic = 0.0;
                    for (unsigned long long observed_count : counts) {
                        double diff = static_cast<double>(observed_count) - expected_count_per_byte;
                        // Avoid division by zero if expected_count is somehow zero (shouldn't happen if total_bytes >= 256)
                        if (expected_count_per_byte > 0) { 
                           chi_squared_statistic += (diff * diff) / expected_count_per_byte;
                        }
                    }
                    return chi_squared_statistic;
                }

                bool check_chi_squared_uniformity(double chi_squared_stat) {
                    // Check if the statistic falls below the critical value for p=0.05
                    // Returning 'true' means we *cannot reject* the null hypothesis of uniformity.
                    return chi_squared_stat <= CHI_SQUARED_CRITICAL_VALUE_DF255_P05;
                }
                ```

    4.  **Result Aggregation and Assessment:**
        *   A minimum file size threshold (e.g., 4096 bytes) **would be** enforced. Files smaller than this **would be** deemed unsuitable for reliable statistical analysis, and the result should indicate this.
        *   Based on the calculated entropy and the Chi-squared test outcome, a final assessment **would be** made (e.g., `LIKELY_ENCRYPTED_OR_COMPRESSED` if entropy is high and the Chi-squared test does not reject uniformity; `LIKELY_NOT_ENCRYPTED` otherwise).
        *   The results, including the calculated entropy, the χ² statistic, the total bytes processed, and the final assessment, **would be** packaged into the `FileStats` structure defined in the API header and returned to the caller.
        *   Returning the raw statistics alongside the assessment provides flexibility for the calling application, which might employ different thresholds or interpretations based on specific needs, analogous to how detailed hit result structures are provided in physics engines rather than simple boolean outcomes.

## 4. C++ Implementation Considerations

This section outlines key C++ implementation details for the static library.

*   **Language Standard:** C++17 is recommended as a minimum baseline for features like `std::filesystem` (if needed for path manipulation, although basic `std::string` handling might suffice) and general modern practices.
*   **Core Headers:** Essential headers include `<fstream>` (file I/O), `<vector>` (byte counts), `<string>` (file path), `<cmath>` (`log2`), `<numeric>` (`std::accumulate`), `<stdexcept>` (potential error handling), and `<limits>` (for `infinity()` if used).
*   **API Design (`.h` Header):**
    *   A clean, minimal header file is essential for a reusable library. **The primary error handling strategy chosen is to return error conditions via the `FileStats::Result` enum**, rather than throwing exceptions. This approach simplifies integration for callers by avoiding mandatory `try-catch` blocks.
    *   The header should define the result structure and the primary analysis function signature:

        ```cpp
        // FileAnalysis.h
        #pragma once
        #include <string>
        #include <vector> // Potentially needed by users if counts are exposed

        struct FileStats {
            double shannon_entropy = 0.0;
            double chi_squared_statistic = 0.0;
            unsigned long long total_bytes = 0;
            enum class Result {
                ASSESSMENT_UNKNOWN,
                LIKELY_ENCRYPTED_OR_COMPRESSED,
                LIKELY_NOT_ENCRYPTED,
                FILE_TOO_SMALL,
                ERROR_READING // Indicates file I/O or other runtime errors
            } assessment = Result::ASSESSMENT_UNKNOWN;
            bool chi_squared_passed = false; // Result of check_chi_squared_uniformity
        };

        // Returns FileStats. Check FileStats.assessment for errors or results.
        FileStats analyze_file_randomness(const std::string& file_path);
        ```

    *   **Error Handling Strategy:** As decided above, file I/O errors (e.g., file not found, permission denied) or other runtime issues during analysis should result in the function returning a `FileStats` object with the `assessment` member set to `Result::ERROR_READING`. Callers should check this member before interpreting other fields like `shannon_entropy` or `chi_squared_statistic`.
*   **Small File Handling:** A check for minimum file size (e.g., `total_bytes < 4096`) should be implemented early in the analysis function. If the threshold is not met, the function should return immediately with the `Result::FILE_TOO_SMALL` assessment.
*   **Performance:** The initial plan utilizes a byte-by-byte reading approach (`std::ifstream::get()`). This prioritizes implementation simplicity and predictable memory usage, which is often suitable for library functions. However, it incurs significant overhead due to the potential for frequent system calls. If performance profiling indicates this method is a bottleneck for large files, **it should be refactored** to use buffered reading. Reading the file in larger chunks (e.g., 4KB, 64KB, or aligned with filesystem block sizes) into a temporary buffer and processing the bytes from that buffer drastically reduces system call frequency and typically yields substantial performance improvements.

## 5. Limitations

It is important to acknowledge the inherent limitations of this statistical approach:

*   **Encryption vs. Compression:** While the preliminary header check aims to identify common compressed formats, the underlying statistical tests (Entropy, Chi-squared) themselves cannot reliably differentiate between strongly encrypted data and *other* effectively compressed data (e.g., formats without common magic numbers, or custom compression schemes) if the header check fails.
*   **Cipher Agnosticism:** The detection identifies statistical randomness characteristic of *most* strong modern ciphers, not specifically AES. Other ciphers (e.g., ChaCha20, Twofish) producing pseudo-random output will likely be flagged similarly if they pass the header check.
*   **Inability to Verify Correctness:** A file passing the randomness checks only suggests the *presence* of encryption or compression, not its *cryptographic soundness*. Weak implementations (e.g., insecure modes like ECB, flawed key generation, improper IV usage) might still produce statistically random output but offer little actual security.
*   **No Key/Parameter Information:** The analysis provides no information regarding the encryption key, initialization vector (IV), mode of operation, or padding scheme used.
*   **Threshold Sensitivity:** The specific numerical thresholds used for entropy (e.g., > 7.9) and the Chi-squared critical value (based on α = 0.05) are heuristic. Optimal values may vary depending on the types of files being analyzed and might require empirical tuning based on testing with a representative dataset.

## 6. Development and Testing Roadmap

The proposed development process follows these stages:

1.  **Project Setup:** Initialize a C++ static library project structure, preferably using CMake for cross-platform build management.
2.  **File Ingestion:** Implement the core file reading logic: open in binary mode, read byte-by-byte, aggregate counts into the `std::vector<unsigned long long>`. Include basic file existence/readability checks.
3.  **Entropy Calculation:** Implement the `calculate_shannon_entropy` function based on the frequency counts.
4.  **Chi-Squared Test:** Implement `calculate_chi_squared` and the corresponding `check_chi_squared_uniformity` function using the chosen critical value comparison.
5.  **API Implementation:** Integrate the components into the main `analyze_file_randomness` function, populate the `FileStats` return structure, implement the minimum file size check, and finalize the error handling strategy.
6.  **Build Verification:** Ensure the project correctly builds into a static library (`.lib`/`.a`). Optionally, create a small test executable that links against the library to verify API usage.
7.  **Empirical Testing:** Conduct thorough testing using a diverse set of files:
    *   Plain text (various encodings/languages)
    *   Source code (`.cpp`, `.py`, `.js`, etc.)
    *   Compiled binaries (ELF, Mach-O)
    *   Shared libraries (`.so`, `.dylib`)
    *   Compressed archives (`.zip`, `.tar.gz`, `.bz2`)
    *   Common media files (`.png`, `.jpg`, `.mp3`, `.wav`)
    *   Known AES-encrypted files (various key sizes/modes if possible).
    *   Analyze results to potentially refine entropy/Chi-squared thresholds.
8.  **Refinement:** Add necessary code comments, improve clarity, and ensure robustness based on testing feedback.
