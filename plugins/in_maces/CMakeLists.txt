set(src
    in_maces.c
    maces_encoders.c
    maces_events.c
    events.c
  )

  FLB_PLUGIN(in_maces "${src}" "-lbsm -lEndpointSecurity")
