set(src
    in_maces.c
  )

  FLB_PLUGIN(in_maces "${src}" "-lbsm -lEndpointSecurity")
