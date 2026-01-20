import Base

#==
# Searches recursively for julia files starting in directory and includes them 
# Returns a symbol storing the name of user_func if successful 
# Returns nothing if func_name is not found
=#

function faasr_import_function_walk(func_name, directory=".")
    ignore_files = [
        "julia_client_stubs.jl",
        "julia_func_helper.jl",
        "julia_user_func_entry.jl"
    ]

    fn = Symbol(func_name)


    for (path, dirs, files) in Base.Filesystem.walkdir(directory)
        for file in files
            if Base.endswith(file, ".jl") && !(file in ignore_files)
                try
                    fn_present = false
                    open("$path/$file") do f
                        if contains(read(f, String), "function $func_name")
                            fn_present = true
                        end
                    end
                    if fn_present
                        include("$path/$file")
                        if isdefined(Main, fn)
                            return fn
                        end
                    end
                catch e
                end
            end
        end
    end
    return nothing

end

