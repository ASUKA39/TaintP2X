/** Generated from CodeQL_Models/taintp2x_models.json; edit the manifest, not this file. */
import javascript

module TaintP2XModels {
  abstract class TaintP2XSource extends DataFlow::Node {
    abstract string getKind();
  }

  abstract class TaintP2XSink extends DataFlow::Node {
    abstract string getCategory();
  }

  class LLMControlledSource extends TaintP2XSource {
    LLMControlledSource() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["acomplete", "agenerate", "ainvoke", "call", "chat", "complete", "createChatCompletion", "generate", "generateContent", "invoke", "stream"] and this = call))
      or
      exists(DataFlow::PropRead read | (read.getPropertyName() in ["content", "text", "response", "output", "customToolSchema"] and this = read))
    }

    override string getKind() { result = "LLMControlled" }
  }

  class FromUrlLLMControlledSource extends TaintP2XSource {
    FromUrlLLMControlledSource() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["fetch", "request", "get", "post"] and this = call))
      or
      exists(DataFlow::PropRead read | (read.getPropertyName() in ["url", "endpoint"] and this = read))
    }

    override string getKind() { result = "FromUrlLLMControlled" }
  }

  class RemoteCodeExecutionSink extends TaintP2XSink {
    RemoteCodeExecutionSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["runInNewContext", "runInThisContext", "compileFunction"] and this = call.getAnArgument()))
      or
      exists(string name, DataFlow::InvokeNode invocation | name in ["eval", "Function", "execScript"] and invocation = DataFlow::globalVarRef(name).getAnInvocation() and this = invocation.getAnArgument())
    }

    override string getCategory() { result = "RemoteCodeExecution" }
  }

  class ExecImportSink extends TaintP2XSink {
    ExecImportSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["require", "import", "dynamicImport"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ExecImportSink" }
  }

  class ExecDeserializationSink extends TaintP2XSink {
    ExecDeserializationSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["load", "unserialize", "deserialize", "parseYaml"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ExecDeserializationSink" }
  }

  class FileContentDeserializationSink extends TaintP2XSink {
    FileContentDeserializationSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["load", "unserialize", "deserialize", "parseYaml", "parse"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "FileContentDeserializationSink" }
  }

  class ExecArgSink extends TaintP2XSink {
    ExecArgSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["exec", "execSync", "spawn", "spawnSync", "fork", "execa", "run"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ExecArgSink" }
  }

  class ExecEnvSink extends TaintP2XSink {
    ExecEnvSink() {
      exists(DataFlow::PropRead read | (read.getPropertyName() in ["env", "envs"] and this = read))
    }

    override string getCategory() { result = "ExecEnvSink" }
  }

  class FileSystem_OtherSink extends TaintP2XSink {
    FileSystem_OtherSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["copyFile", "copyFileSync", "rename", "renameSync", "unlink", "unlinkSync", "rm", "rmSync", "mkdir", "mkdirSync", "chmod", "chown"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "FileSystem_Other" }
  }

  class FileSystem_ReadWriteSink extends TaintP2XSink {
    FileSystem_ReadWriteSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "open", "openSync", "createReadStream", "createWriteStream", "read", "write"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "FileSystem_ReadWrite" }
  }

  class EmailSendSink extends TaintP2XSink {
    EmailSendSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["sendMail", "sendmail", "setContent", "addAttachment", "addAlternative"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "EmailSend" }
  }

  class SQLSink extends TaintP2XSink {
    SQLSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["query", "execute", "raw", "$queryRaw", "$executeRaw", "findBySql"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "SQL" }
  }

  class XSSSink extends TaintP2XSink {
    XSSSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["send", "sendFile", "write", "render", "innerHTML", "dangerouslySetInnerHTML"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "XSS" }
  }

  class FormatStringSink extends TaintP2XSink {
    FormatStringSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["format", "sprintf", "formatString"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "FormatString" }
  }

  class ReturnedToUserSink extends TaintP2XSink {
    ReturnedToUserSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["send", "json", "end", "reply", "respond"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ReturnedToUser" }
  }

  class ResponseHeaderValueSink extends TaintP2XSink {
    ResponseHeaderValueSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["setHeader", "header", "set", "append"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ResponseHeaderValue" }
  }

  class ResponseHeaderNameSink extends TaintP2XSink {
    ResponseHeaderNameSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["setHeader", "header", "set", "append"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "ResponseHeaderName" }
  }

  class LoggingSink extends TaintP2XSink {
    LoggingSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["log", "info", "warn", "error", "debug", "trace"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "Logging" }
  }

  class SSRFSink extends TaintP2XSink {
    SSRFSink() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["fetch", "request", "get", "post", "put", "delete", "head", "axios"] and this = call.getAnArgument()))
    }

    override string getCategory() { result = "SSRFSink" }
  }

  class TaintP2XSanitizer extends DataFlow::Node {
    TaintP2XSanitizer() {
      exists(DataFlow::CallNode call | (call.getCalleeName() in ["escapeHtml", "sanitizeHtml", "sanitize", "DOMPurify"] and this = call))
    }
  }

  predicate isFileOperationCall(DataFlow::CallNode call) {
    call.getCalleeName() in ["readFile", "readFileSync", "read", "createReadStream", "readdir", "readdirSync"]
  }
}
