# unction to help "source" the R files in the system 
faasr_source_r_files <- function(directory = "."){
  r_files <- list.files(path = directory, pattern="\\.R$", recursive=TRUE, full.names=TRUE)
  for (rfile in r_files){
    if (basename(rfile) != "r_func_entry.R" && basename(rfile) != "r_func_helper.R" && basename(rfile) != "http_wrappers.R") {
      cat("{\"faasr_source_r_files\":\"Sourcing R file", basename(rfile),"\"}\n")
      tryCatch(expr=source(rfile), error=function(e){
        cat("{\"faasr_source_r_files\":\"R file ", basename(rfile), " has following source error: ", as.character(e), "\"}\n")
	    }
      )
    }
  }
}


# Run user function
faasr_run_user_function <- function(func_name, user_args){ 
  # Check that function is in namespace
  user_function = tryCatch(expr=get(func_name), error=function(e){
    err_msg <- paste0('{\"faasr_user_function\":\"Cannot find function, ', func_name,', check the name and sources\"}', "\n")
    message(err_msg)
    faasr_log(err_msg)
    faasr_exit()
    }
  )
  
  
  # Use do.call to use user_function with arguments
  # try do.call and if there's an error, return error message and stop the function
  faasr_result <- withCallingHandlers(expr=do.call(user_function, user_args), error=function(e){
    nat_err_msg <- paste0('\"faasr_user_function\":Errors in the user function - ', as.character(e))
    err_msg <- paste0('{\"faasr_user_function\":\"Errors in the user function, ', func_name, ', check the log for the detail\"}', "\n")
    trace <- paste(capture.output(sys.calls()), collapse="\n")
    faasr_log(nat_err_msg)
    faasr_log(trace)
    message(err_msg)
    faasr_exit(traceback=trace)
    }
  )

  return(faasr_result)
}



