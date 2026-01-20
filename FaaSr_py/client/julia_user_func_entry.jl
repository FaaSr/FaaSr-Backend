include("./julia_func_helper.jl")
include("./julia_client_stubs.jl")


function run_julia_function(func_name, args, invocationID)

    user_function = nothing
    try
        user_function = faasr_import_function_walk(
            func_name, "/tmp/functions/$(invocationID)"
        )
    catch e
        err_msg = string("failed to get the user function", e)
        faasr_exit(err_msg)
        return
    end

    if user_function == nothing
        err_msg = "failed to find user function $func_name"
        faasr_exit(err_msg)
        return
    end



    result = Dict()

    try
        arg_array = collect(values(args))

        fn_expr = Expr(:call, user_function, arg_array...)
        return_value = eval(fn_expr) 

        if return_value != nothing
            result = return_value
        end

    catch e
        err_msg = string("Error while running user function: ", e)
        faasr_exit(err_msg)
    end

    faasr_return(result)
end

if abspath(PROGRAM_FILE) == @__FILE__
    func_name = ARGS[1]
    args_raw = ARGS[2]
    args = JSON.parse(args_raw)
    invocationID = ARGS[3]
    run_julia_function(func_name, args, invocationID)
end

    





