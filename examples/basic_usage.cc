// examples/basic_usage.cc

#include "FileAnalysis.hh" // Include the library header
#include <iostream>
#include <string>
#include <vector>
#include <sstream> // For string stream
#include <iomanip> // For std::fixed, std::setprecision
#include <map>     // For JSON-like structures (conceptually)
#include <filesystem> // For directory iteration (C++17)
#include <utility> // For std::pair

// Helper function to convert the StatusFlags bitfield to a readable string
std::string flagsToString(StatusFlags flags) {
    if (flags == StatusFlags::NONE) {
        return "No analysis performed or unknown error.";
    }

    std::stringstream ss;
    bool first_flag = true;

    auto add_flag_string = [&](StatusFlags flag, const char* desc) {
        if (has_flag(flags, flag)) {
            if (!first_flag) ss << ", ";
            ss << desc;
            first_flag = false;
        }
    };

    // Check for primary outcomes first
    if (has_flag(flags, StatusFlags::ERROR_READING)) {
        ss << "Error Reading File";
        first_flag = false;
    } else if (has_flag(flags, StatusFlags::MAGIC_NUMBER_MATCHED)) {
        ss << "Known File Type (Header Matched)";
        // If magic matched, it's also likely not encrypted
        add_flag_string(StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED, "Likely Not Encrypted");
        first_flag = false; // Prevent further flags unless needed for debugging
    } else if (has_flag(flags, StatusFlags::FILE_TOO_SMALL)) {
        ss << "File Too Small for Analysis";
        // If too small, also likely not encrypted
         add_flag_string(StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED, "Likely Not Encrypted");
         first_flag = false;
    }

    // Add assessment details if stats were calculated (and no early exit above)
    if (has_flag(flags, StatusFlags::STATS_CALCULATED) && first_flag) { 
         // Use the specific heuristic flags
         add_flag_string(StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED, "Heuristically Encrypted (High Randomness)");
         add_flag_string(StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED, "Heuristically Compressed (High Randomness)");
         // Also add the general NOT_ENCRYPTED if applicable
         add_flag_string(StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED, "Likely Not Encrypted (Low Entropy/Failed Chi2)");
    } else if (first_flag) { // If stats weren't calculated for other reasons (shouldn't happen?)
         add_flag_string(StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED, "Likely Not Encrypted (Analysis Skipped/Incomplete)");
    }
    
    // Optionally add SUCCESS flag for clarity if no error occurred
    if (has_flag(flags, StatusFlags::SUCCESS) && !has_flag(flags, StatusFlags::ERROR_READING)) {
         if (!first_flag) ss << ", ";
         ss << "Analysis Successful";
    }

    if (ss.str().empty()) { // Fallback if somehow no primary flag was set
        return "Analysis completed with undefined status.";
    }

    return ss.str();
}

// Helper function to print flag description
void print_flag_description(StatusFlags flag, const std::string& description) {
    std::cout << "  - 0x" << std::hex << static_cast<uint32_t>(flag) << std::dec << ": " << description << "\n";
}

// Helper function to print usage instructions
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] <file_path>\n";
    std::cout << "   or: " << program_name << " [options] -d <directory_path> [-r]\n";
    std::cout << "   or: " << program_name << " --help | -h\n\n";
    std::cout << "Analyzes a file or files within a directory for potential encryption/compression\n";
    std::cout << "based on statistical properties.\n\n";
    std::cout << "Options:\n";
    std::cout << "  <file_path>        Path to a single file to analyze.\n";
    std::cout << "  -d, --directory DIR Path to a directory to scan for files.\n";
    std::cout << "  -r, --recursive    Recursively scan subdirectories (requires -d).\n";
    std::cout << "  -f, --format FMT   Set output format (text, json, yaml, xml). Default: text\n";
    std::cout << "  -h, --help         Show this help message and exit.\n\n";
    std::cout << "Status Flags returned (bitwise combined, shown in hex):\n";
    print_flag_description(StatusFlags::SUCCESS, "Analysis completed without file/read errors.");
    print_flag_description(StatusFlags::ERROR_READING, "File couldn't be opened or read error occurred.");
    print_flag_description(StatusFlags::FILE_TOO_SMALL, "File was too small for statistical analysis.");
    print_flag_description(StatusFlags::MAGIC_NUMBER_MATCHED, "A known file signature was found (analysis stopped).");
    print_flag_description(StatusFlags::STATS_CALCULATED, "Entropy and Chi-squared were calculated.");
    print_flag_description(StatusFlags::CHI_SQUARED_PASSED, "Chi-squared test passed (consistent with uniform distribution).");
    print_flag_description(StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED, "Assessment: Likely NOT Encrypted/Compressed (Low Entropy, Failed Chi2, Magic Match, or Too Small).");
    print_flag_description(StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED, "Assessment: Heuristically ENCRYPTED (Very High Randomness - USE WITH CAUTION!).");
    print_flag_description(StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED, "Assessment: Heuristically COMPRESSED (High Randomness - USE WITH CAUTION!).");
    std::cout << "\n";
}

// --- Output Formatting --- //

enum class OutputFormat {
    TEXT,
    JSON,
    YAML,
    XML
};

// Forward declarations for print functions
void print_single_result_text(const FileAnalysisResult& result);
void print_batch_results_json(const std::vector<FileAnalysisResult>& results);
void print_batch_results_yaml(const std::vector<FileAnalysisResult>& results);
void print_batch_results_xml(const std::vector<FileAnalysisResult>& results);

// --- Main Logic --- //

int main(int argc, char* argv[]) {
    std::string file_path;
    std::string dir_path;
    bool recursive = false;
    OutputFormat format = OutputFormat::TEXT;
    AnalysisConfig config = {}; // Create default config
    // TODO: Add command line options to modify config (e.g., --min-size, --entropy-thresh)

    // --- Argument Parsing State --- 
    enum class Expecting { NONE, DIR, FORMAT };
    Expecting expecting = Expecting::NONE;

    std::vector<std::string> args(argv + 1, argv + argc);

    // --- Manual Argument Parsing Loop --- 
    for (const auto& arg : args) {
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--format" || arg == "-f") {
            expecting = Expecting::FORMAT;
        } else if (arg == "--directory" || arg == "-d") {
            expecting = Expecting::DIR;
        } else if (arg == "--recursive" || arg == "-r") {
            recursive = true;
            expecting = Expecting::NONE; // Recursive obviously  doesn't take a value
        } else if (expecting == Expecting::FORMAT) {
            if (arg == "json") format = OutputFormat::JSON;
            else if (arg == "yaml") format = OutputFormat::YAML;
            else if (arg == "xml") format = OutputFormat::XML;
            else if (arg == "text") format = OutputFormat::TEXT;
            else {
                std::cerr << "Error: Unknown format specified: " << arg << std::endl;
                print_usage(argv[0]);
                return 1;
            }
            expecting = Expecting::NONE;
        } else if (expecting == Expecting::DIR) {
            dir_path = arg;
            expecting = Expecting::NONE;
        } else if (file_path.empty() && dir_path.empty() && expecting == Expecting::NONE) { 
            // Only take as file path if we are not expecting anything else and haven't got a path yet
            file_path = arg;
        } else {
            std::cerr << "Error: Unexpected argument or multiple paths specified: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    // --- Validate Arguments ---
    if (expecting == Expecting::FORMAT) {
         std::cerr << "Error: Missing format type after --format/-f option." << std::endl;
         print_usage(argv[0]);
         return 1;
    }
    if (expecting == Expecting::DIR) {
         std::cerr << "Error: Missing directory path after --directory/-d option." << std::endl;
         print_usage(argv[0]);
         return 1;
    }
    if (!file_path.empty() && !dir_path.empty()) {
        std::cerr << "Error: Cannot specify both a file path and a directory path." << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    if (file_path.empty() && dir_path.empty()) {
        std::cerr << "Error: No file path or directory path provided." << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    if (recursive && dir_path.empty()) {
        std::cerr << "Error: Recursive flag -r requires a directory path (-d)." << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    // --- Collect results --- 
    std::vector<FileAnalysisResult> analysis_results;
    bool overall_success = true;

    try { // Wrap analysis in try-catch for potential filesystem errors from library
        if (!file_path.empty()) {
            // Analyze single file
            FileStats stats = analyze_file_randomness(file_path, config);
            // Use make_preferred() for consistent path separators in output
            analysis_results.push_back({std::filesystem::path(file_path).make_preferred().string(), stats});
            if (!has_flag(stats.status_flags, StatusFlags::SUCCESS)) {
                overall_success = false;
            }
        } else {
            // Call the LIBRARY function to handle iteration
            auto dir_results = analyze_directory(dir_path, config, recursive);
            analysis_results = std::move(dir_results);
            
            // Check success status for the whole batch
            for(const auto& result : analysis_results) {
                if (!has_flag(result.stats.status_flags, StatusFlags::SUCCESS)) {
                    overall_success = false;
                 }
            }
            // Print iterative text results *after* collecting all results if format is TEXT
            if (format == OutputFormat::TEXT) {
                for(const auto& result : analysis_results) {
                    print_single_result_text(result);
                    std::cout << "\n";
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error during analysis: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error during analysis: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred during analysis." << std::endl;
        return 1;
    }
    

    // --- Output Results based on format (excluding TEXT, handled above) ---
    switch (format) {
        case OutputFormat::JSON:
            print_batch_results_json(analysis_results);
            break;
        case OutputFormat::YAML:
            print_batch_results_yaml(analysis_results);
            break;
        case OutputFormat::XML:
            print_batch_results_xml(analysis_results);
            break;
        case OutputFormat::TEXT:
             // Handled iteratively above for directories,
             // or handled here for single file case (if results not empty)
             if (!file_path.empty() && !analysis_results.empty()) {
                 // Text format for single file is printed here now
                 print_single_result_text(analysis_results[0]);
             } else if (dir_path.empty() && analysis_results.empty()) {
                 // This case means no files were found or an error occurred before analysis
                 std::cerr << "Info: No files analyzed or found." << std::endl;
                 // Return success if no *errors* occurred, even if no files found
                 overall_success = true; 
             }
            break;
    }

    return overall_success ? 0 : 1;
}

// --- Output Formatting Implementations --- //

// Prints results for a SINGLE file in TEXT format
void print_single_result_text(const FileAnalysisResult& result) {
    const auto& stats = result.stats;
    std::cout << "--- Analysis Results (TEXT) for: " << result.file_path << " ---" << std::endl;
    std::cout << "File Size Processed: " << stats.total_bytes << " bytes" << std::endl;

    // Check for critical errors first
    if (has_flag(stats.status_flags, StatusFlags::ERROR_READING)) {
        std::cerr << "Error: Could not read the file." << std::endl;
    } else if (has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL)) {
        std::cout << "Info: File is too small for reliable statistical analysis." << std::endl;
    } else if (has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED)) {
        std::cout << "Info: Known file signature (magic number) detected. Statistical analysis skipped." << std::endl;
        std::cout << "Assessment: Likely Not Encrypted (Known Format)" << std::endl;
    }

    // If stats were calculated, print them
    if (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED)) {
        std::cout << std::fixed << std::setprecision(5); // Format floating point output
        std::cout << "Shannon Entropy: " << stats.shannon_entropy << " bits/byte" << std::endl;
        std::cout << "Chi-Squared Statistic: " << stats.chi_squared_statistic << std::endl;
        std::cout << "Chi-Squared Test Passed (Uniformity Check): "
                  << (has_flag(stats.status_flags, StatusFlags::CHI_SQUARED_PASSED) ? "Yes" : "No") << std::endl;
    } else if (!has_flag(stats.status_flags, StatusFlags::ERROR_READING) &&
               !has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL) &&
               !has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED)) {
         std::cout << "Info: Statistical analysis was not performed (check flags)." << std::endl;
    }

    // Print final assessment based on flags (only if not determined by magic number/size)
    if (!has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED) &&
        !has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL) &&
        !has_flag(stats.status_flags, StatusFlags::ERROR_READING))
    {
        // Check for the new heuristic flags first
        if (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED)) {
            std::cout << "Assessment: Heuristically Encrypted (High Randomness - Use With Caution!)" << std::endl;
        } else if (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED)) {
             std::cout << "Assessment: Heuristically Compressed (High Randomness - Use With Caution!)" << std::endl;
        } else if (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED)) {
             std::cout << "Assessment: Likely Not Encrypted/Compressed" << std::endl;
        } else {
            std::cout << "Assessment: Inconclusive (check flags)" << std::endl;
        }
    }

    std::cout << "Status Flags: 0x" << std::hex << static_cast<uint32_t>(stats.status_flags) << std::dec << std::endl;
}

// Helper function to print a single result as a JSON object (no outer brackets/commas)
void print_json_object(const FileAnalysisResult& result, bool add_comma) {
    const auto& stats = result.stats;
    std::cout << "  {\n";
    std::cout << "    \"filename\": \"" << result.file_path << "\",\n"; // TODO: Escape result.file_path
    std::cout << "    \"file_size_processed\": " << stats.total_bytes << ",\n";
    std::cout << "    \"status_flags\": " << static_cast<uint32_t>(stats.status_flags) << ",\n";
    std::cout << "    \"error_reading\": " << (has_flag(stats.status_flags, StatusFlags::ERROR_READING) ? "true" : "false") << ",\n";
    std::cout << "    \"file_too_small\": " << (has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL) ? "true" : "false") << ",\n";
    std::cout << "    \"magic_number_matched\": " << (has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED) ? "true" : "false") << ",\n";
    std::cout << "    \"stats_calculated\": " << (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED) ? "true" : "false") << ",\n";
    if (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED)) {
        std::cout << std::fixed << std::setprecision(8);
        std::cout << "    \"shannon_entropy\": " << stats.shannon_entropy << ",\n";
        std::cout << "    \"chi_squared_statistic\": " << stats.chi_squared_statistic << ",\n";
        std::cout << "    \"chi_squared_passed\": " << (has_flag(stats.status_flags, StatusFlags::CHI_SQUARED_PASSED) ? "true" : "false") << ",\n";
    }
    std::cout << "    \"assessment_likely_not_encrypted\": " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED) ? "true" : "false") << ",\n";
    std::cout << "    \"assessment_heuristic_encrypted\": " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED) ? "true" : "false") << ",\n";
    std::cout << "    \"assessment_heuristic_compressed\": " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED) ? "true" : "false") << "\n";
    std::cout << "  }" << (add_comma ? "," : "") << "\n";
}

void print_batch_results_json(const std::vector<FileAnalysisResult>& results) {
    std::cout << "[\n"; // Start JSON array
    for (size_t i = 0; i < results.size(); ++i) {
        print_json_object(results[i], (i < results.size() - 1)); // Add comma except for last item
    }
    std::cout << "]\n"; // End JSON array
}

// Helper function to print a single result as a YAML map item
void print_yaml_map_item(const FileAnalysisResult& result) {
    const auto& stats = result.stats;
    std::cout << "- filename: " << result.file_path << "\n"; // TODO: Escape/quote result.file_path if needed
    std::cout << "  file_size_processed: " << stats.total_bytes << "\n";
    std::cout << "  status_flags: " << static_cast<uint32_t>(stats.status_flags) << "\n";
    std::cout << "  error_reading: " << (has_flag(stats.status_flags, StatusFlags::ERROR_READING) ? "true" : "false") << "\n";
    std::cout << "  file_too_small: " << (has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL) ? "true" : "false") << "\n";
    std::cout << "  magic_number_matched: " << (has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED) ? "true" : "false") << "\n";
    std::cout << "  stats_calculated: " << (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED) ? "true" : "false") << "\n";
    if (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED)) {
        std::cout << std::fixed << std::setprecision(8);
        std::cout << "  shannon_entropy: " << stats.shannon_entropy << "\n";
        std::cout << "  chi_squared_statistic: " << stats.chi_squared_statistic << "\n";
        std::cout << "  chi_squared_passed: " << (has_flag(stats.status_flags, StatusFlags::CHI_SQUARED_PASSED) ? "true" : "false") << "\n";
    }
    std::cout << "  assessment_likely_not_encrypted: " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED) ? "true" : "false") << "\n";
    std::cout << "  assessment_heuristic_encrypted: " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED) ? "true" : "false") << "\n";
    std::cout << "  assessment_heuristic_compressed: " << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED) ? "true" : "false") << "\n";
}

void print_batch_results_yaml(const std::vector<FileAnalysisResult>& results) {
    std::cout << "---" << "\n"; // Start YAML document
    for (const auto& result : results) {
        print_yaml_map_item(result);
    }
    std::cout << "...\n"; // End YAML document
}

// Helper function to print a single result as an XML element
void print_xml_element(const FileAnalysisResult& result) {
     const auto& stats = result.stats;
    // Use file_path and add placeholder comment for escaping
    // TODO: Escape result.file_path for XML attribute value
    std::cout << "  <AnalysisResult filename=\"" << result.file_path << "\">\n";
    std::cout << "    <FileSizeProcessed>" << stats.total_bytes << "</FileSizeProcessed>\n";
    std::cout << "    <StatusFlags>" << static_cast<uint32_t>(stats.status_flags) << "</StatusFlags>\n";
    std::cout << "    <ErrorReading>" << (has_flag(stats.status_flags, StatusFlags::ERROR_READING) ? "true" : "false") << "</ErrorReading>\n";
    std::cout << "    <FileTooSmall>" << (has_flag(stats.status_flags, StatusFlags::FILE_TOO_SMALL) ? "true" : "false") << "</FileTooSmall>\n";
    std::cout << "    <MagicNumberMatched>" << (has_flag(stats.status_flags, StatusFlags::MAGIC_NUMBER_MATCHED) ? "true" : "false") << "</MagicNumberMatched>\n";
    std::cout << "    <StatsCalculated>" << (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED) ? "true" : "false") << "</StatsCalculated>\n";
    if (has_flag(stats.status_flags, StatusFlags::STATS_CALCULATED)) {
        std::cout << std::fixed << std::setprecision(8);
        std::cout << "    <ShannonEntropy>" << stats.shannon_entropy << "</ShannonEntropy>\n";
        std::cout << "    <ChiSquaredStatistic>" << stats.chi_squared_statistic << "</ChiSquaredStatistic>\n";
        std::cout << "    <ChiSquaredPassed>" << (has_flag(stats.status_flags, StatusFlags::CHI_SQUARED_PASSED) ? "true" : "false") << "</ChiSquaredPassed>\n";
    }
    std::cout << "    <AssessmentLikelyNotEncrypted>" << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_LIKELY_NOT_ENCRYPTED) ? "true" : "false") << "</AssessmentLikelyNotEncrypted>\n";
    std::cout << "    <AssessmentHeuristicEncrypted>" << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_ENCRYPTED) ? "true" : "false") << "</AssessmentHeuristicEncrypted>\n";
    std::cout << "    <AssessmentHeuristicCompressed>" << (has_flag(stats.status_flags, StatusFlags::ASSESSMENT_HEURISTIC_COMPRESSED) ? "true" : "false") << "</AssessmentHeuristicCompressed>\n";
    std::cout << "  </AnalysisResult>\n";
}

void print_batch_results_xml(const std::vector<FileAnalysisResult>& results) {
    std::cout << R"(<?xml version="1.0" encoding="UTF-8"?>)" << "\n";
    std::cout << "<BatchAnalysisResults>\n";
    for (const auto& result : results) {
        print_xml_element(result);
    }
    std::cout << "</BatchAnalysisResults>\n";
}