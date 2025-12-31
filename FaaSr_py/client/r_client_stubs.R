library(httr)

faasr_log <- function(log_message) {
    request_json <- list(
        "ProcedureID" = "faasr_log",
        Arguments = list(
            "log_message" = log_message
        )
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Success)
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_put_file <- function(local_file, remote_file, server_name="", local_folder=".", remote_folder=".") {
    request_json <- list(
        "ProcedureID" = "faasr_put_file",
        "Arguments" = list("local_file" = local_file, 
                    "remote_file" = remote_file,
                    "server_name" = server_name,
                    "local_folder" = local_folder,
                    "remote_folder" = remote_folder
        )
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Success)
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}
    

faasr_get_file <- function(local_file, remote_file, server_name="", local_folder=".", remote_folder=".") {
    request_json <- list(
        "ProcedureID" = "faasr_get_file",
        "Arguments" = list ("local_file" = local_file, 
                    "remote_file" = remote_file,
                    "server_name" = server_name,
                    "local_folder" = local_folder,
                    "remote_folder" = remote_folder
        )
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Success)
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}

faasr_delete_file <- function(remote_file, server_name="", remote_folder="") {
    request_json <- list(
        "ProcedureID" = "faasr_delete_file",
        "Arguments" = list("remote_file" = remote_file, 
                    "server_name" = server_name,
                    "remote_folder" = remote_folder
        )
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Success)
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_get_folder_list <- function(server_name="", prefix = "") {
    request_json <- list(
        "ProcedureID" = "faasr_get_folder_list",
        "Arguments" = list("server_name" = server_name,
                     "prefix" = prefix
                     )
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)
    
    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Data$folder_list)
    } else {
        err_msg <- "Failed to get folder list"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_get_s3_creds <- function(server_name = "") {
    request_json <- list(
        "ProcedureID" = "faasr_get_s3_creds",
        "Arguments" = list("server_name" = server_name)
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body = request_json, encode = "json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Data$s3_creds)
    } else {
        err_msg <- "Failed to get S3 credentials"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_secret <- function(secret_name) {
    if (is.null(secret_name) || secret_name == "") {
        err_msg <- "faasr_secret: secret_name cannot be empty or NULL"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
    request_json <- list(
        "ProcedureID" = "faasr_secret",
        "Arguments" = list("secret_name" = secret_name)
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body = request_json, encode = "json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Data$secret_value)
    } else {
        err_msg <- "Failed to get secret from server"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_invocation_id <- function() {
    request_json <- list(
        "ProcedureID" = "faasr_invocation_id",
        "Arguments" = list()
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body = request_json, encode = "json")
    response_content <- content(r)

    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Data$invocation_id)
    } else {
        err_msg <- "Failed to get invocation ID"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_arrow_s3_bucket <- function(server_name = "", faasr_prefix = "") {
    # get s3 creds
    creds <- faasr_get_s3_creds(server_name = server_name)

    if (faasr_prefix != "") {
        bucket <- paste0(creds$bucket, "/", faasr_prefix)
    } else {
        bucket <- creds$bucket
    }

    if (creds$anonymous) {
        s3 <- arrow::s3_bucket(
            bucket = bucket,
            endpoint_override = creds$endpoint,
            region = creds$region,
            anonymous = TRUE
        )
    } else {
        s3 <- arrow::s3_bucket(
            bucket = bucket,
            endpoint_override = creds$endpoint,
            access_key = creds$access_key,
            secret_key = creds$secret_key,
            region = creds$region
        )
    }

    return(s3)
}


faasr_rank <- function(rank_value=NULL) {
    request_json <- list(
        "ProcedureID" = "faasr_invocation_id",
        "Arguments" = list()
    )
    r <- POST("http://127.0.0.1:8000/faasr-action", body=request_json, encode="json")
    response_content <- content(r)
    if (!is.null(response_content$Success) && response_content$Success) {
        return (response_content$Data)
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_return <- function(return_value=NULL) {
    if (is.null(return_value)) {
        quit(status = 0, save = "no")
    } else {
        return_json = list(
            FunctionResult = return_value
        )
    }

    r <- POST("http://127.0.0.1:8000/faasr-return", body=return_json, encode="json")
    if (!is.null(r$status_code) && r$status_code == 200) {
        response_content <- content(r)
        if (!is.null(response_content$Success) && response_content$Success) {
            quit(status = 0, save = "no")
        } else {
            err_msg <- "Request to FaaSr RPC failed"
            message(err_msg)
            faasr_exit(error=TRUE)
        }
    } else {
        err_msg <- paste0("HTTP request failed with status code: ", r$status_code)
        faasr_exit(error=TRUE, message=err_msg)
        quit(status = 1, save = "no")
    }
}


faasr_exit <- function(message=NULL, error=TRUE, traceback=NULL) {
    exit_json <- list(
        Error = error,
        Message = message,
        Traceback = traceback
    )
    r <- POST("http://127.0.0.1:8000/faasr-exit", body=exit_json, encode="json")
    response_content <- content(r)
    if (!is.null(response_content$Success) && response_content$Success) {
        quit(status = 0, save = "no")
    } else {
        err_msg <- "Request to FaaSr RPC failed"
        message(err_msg)
        quit(status = 1, save = "no")
    }
}