# physical specification for none backend

{
  hoshijiro =
  { config, lib, pkgs, resources, ...}:
  { deployment.targetEnv = "none";
    deployment.targetHost = "192.168.1.215";

    # Workaround for error: [Errno 7] Argument list too long
    deployment.hasFastConnection = true;
  };
}
