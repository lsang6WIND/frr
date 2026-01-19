// SPDX-License-Identifier: GPL-2.0-or-later
/* L2VPN header
 * Copyright (C) 2025 6WIND
 */
#ifndef _FRR_BGP_L2VPN_H
#define _FRR_BGP_L2VPN_H

extern void bgp_l2vpn_init(void);
extern struct l2vpn_svc *bgp_l2vpn_vpws_evi_match(uint32_t ethtag);
extern void bgp_l2vpn_svc_update_status(struct zapi_pw_status *zpw);
extern bool bgp_evpn_vpws_vni_changed(struct bgp *bgp, struct bgpevpn *vpn,
				      vrf_id_t tenant_vrf_id);
extern uint32_t bgp_evpn_vpws_vni_del(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_l2vpn_vpws_vni_rd_update(struct bgp *bgp, struct bgpevpn *vpn, bool withdraw);
extern uint32_t bgp_l2vpn_vpws_es_add(esi_t esi);
struct zebra_pw;
extern void bgp_l2vpn_vpws_zebra_set(struct bgp *bgp, struct l2vpn_svc *l2vpn_svc, bool on);
extern void bgp_l2vpn_ifp_up(struct interface *ifp, bool up);

#endif /* _FRR_BGP_L2VPN_H */
