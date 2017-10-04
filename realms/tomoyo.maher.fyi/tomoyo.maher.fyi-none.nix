# physical specification for none backend

{
  tomoyo =
  { config, lib, pkgs, resources, ...}:
  { deployment.targetEnv = "none";
    deployment.targetHost = "114.111.153.166";

    # Workaround for error: [Errno 7] Argument list too long
    deployment.hasFastConnection = true;
  };
}
