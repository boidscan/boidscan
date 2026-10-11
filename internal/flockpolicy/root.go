package flockpolicy

// Root is the first maintainer set; later sets come only from policies it
// signed. Empty until the first maintainer key exists, so release builds
// cannot accept any policy and never sweep.
var Root = Maintainers{Threshold: 1}
