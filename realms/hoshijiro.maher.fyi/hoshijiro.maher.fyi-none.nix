# physical specification for none backend

{
  hoshijiro =
  { config, lib, pkgs, resources, ...}:
  { deployment.targetEnv = "none";
    deployment.targetHost = "192.168.1.215";
    deployment.hasFastConnection = true;
  };
}
