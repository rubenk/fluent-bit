set(src
    in_maces.c
    events.c
  )

  FLB_PLUGIN(in_maces "${src}" "-lbsm -lEndpointSecurity")
