package flockpolicy

// Root is the first maintainer set; later sets come only from policies it signed.
var Root = Maintainers{
	Keys:      []string{"p7pq44zppib4uviomfk4nqonpx4wdtlf5mtaiqevbzm2p2t2mhfq"},
	Threshold: 1,
}
