# physical specification for none backend

{
  tomoyo =
  { config, lib, pkgs, resources, ...}:
  { deployment.targetEnv = "none";
    deployment.targetHost = "192.168.1.245";

    # Workaround for error: [Errno 7] Argument list too long
    deployment.hasFastConnection = true;
  };
}
