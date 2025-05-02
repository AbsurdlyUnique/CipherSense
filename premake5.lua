-- premake5.lua

-- Define the workspace
workspace "EncryptionDetector"
    configurations { "Debug", "Release" }
    -- Specify C++17 as the minimum standard for the workspace
    cppdialect "C++17"
    -- Define output directory structure
    -- bin/(config) for executables/libraries
    -- obj/(config)/(project) for intermediate files
    targetdir "bin/%{cfg.buildcfg}"
    objdir "obj/%{cfg.buildcfg}/%{prj.name}"

-- Define the static library project
project "EncryptionDetectorLib"
    kind "StaticLib"  -- Creates .a (Linux/macOS), .lib (Windows)
    language "C++"

    -- Specify source and header files using .cc and .hh convention
    files { 
        "src/**.cc", 
        "include/**.hh" 
    }

    -- Make the include directory available to this project and consumers
    includedirs { 
        "include" 
    }
    -- Make include dir public for consumers of the library
    defines { "ENCRYPTIONDETECTORLIB_STATIC" } -- Define for static lib builds if needed
    visibility "Default" -- Make symbols visible for static lib

    -- Configuration-specific settings
    filter "configurations:Debug"
        defines { "DEBUG" } -- Define DEBUG macro for debug builds
        symbols "On"        -- Enable debug symbols

    filter "configurations:Release"
        defines { "NDEBUG" } -- Define NDEBUG macro for release builds
        optimize "On"       -- Enable optimizations

-- Optional: Define a consuming executable for testing
project "BasicUsageExample"
    kind "ConsoleApp"
    language "C++"
    -- Point to the example source file
    files { "examples/basic_usage.cc" }

    -- Link against our static library
    links { "EncryptionDetectorLib" }

    -- Ensure the example can find the library's headers
    includedirs { "include" } 

    -- Configuration-specific settings for the example app
    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "On"

-- Custom Action: Encrypt test file
newaction {
    trigger     = "encrypt",
    description = "Encrypts AES.md to AES.md.enc using OpenSSL",
    execute     = function ()
        print("Encrypting AES.md...")
        local input_file = "AES.md"
        local output_file = "AES.md.enc"
        -- Check if input file exists first
        if os.isfile(input_file) then
            -- Use a simple password 'password' for reproducibility
            local command = string.format("openssl enc -aes-256-cbc -salt -in %s -out %s -k password", 
                                        input_file, output_file)
            print("Executing: " .. command)
            -- os.execute returns true on success (0), nil if command fails to execute, false otherwise
            local ok, reason, status = os.execute(command)
            if ok then -- Check if command executed and returned success (exit code 0)
                print("Successfully created " .. output_file)
            else
                -- Provide more detail if possible
                if reason == "exit" then
                    print(string.format("Error encrypting file (openssl command failed with exit code: %s)", status))
                elseif reason == "signal" then
                     print(string.format("Error encrypting file (openssl command terminated by signal: %s)", status))
                else 
                    print("Error: Failed to execute openssl command.")
                end
            end
        else
            print("Error: " .. input_file .. " not found. Please ensure it exists.")
        end
    end
}

-- Custom Action: Clean up test files
newaction {
    trigger     = "clean_testfiles",
    description = "Removes generated test files (test.txt, AES.md.enc)",
    execute     = function ()
        print("Cleaning test files...")
        -- os.remove returns true on success, or nil + error message on failure
        local ok_txt, err_txt = os.remove("test.txt")
        if ok_txt then print("Removed test.txt") elseif err_txt and not string.find(err_txt, "No such file") then print("Could not remove test.txt: " .. err_txt) end
        
        local output_file = "AES.md.enc"
        local ok_enc, err_enc = os.remove(output_file)
        if ok_enc then print("Removed " .. output_file) elseif err_enc and not string.find(err_enc, "No such file") then print("Could not remove " .. output_file .. ": " .. err_enc) end
        
        -- Report if nothing was done, ignoring "file not found" errors
        if not ok_txt and not ok_enc and (err_txt and not string.find(err_txt, "No such file")) and (err_enc and not string.find(err_enc, "No such file")) then
             print("Error removing test files.")
        elseif not ok_txt and not ok_enc then
             print("No test files found to remove.")
        end
    end
}

-- Note: The built-in 'clean' action for gmake often just removes obj/bin dirs.
-- This custom 'clean_testfiles' action specifically targets our test artifacts. 