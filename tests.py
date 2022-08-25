import unittest
import yaml
import yml_transform
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
logging.disable(logging.DEBUG)
logging.disable(logging.INFO)

class YMLTests(unittest.TestCase):
    SW_TEMPLATE = """
actions:
    drop_action:
        primitives:
            - mark_to_drop
    notify_action:
        primitives:
            - notify
    l2_tagged_interface_action:
        primitives:
            - output
    l2_untagged_interface_action:
        primitives:
            - pop_vlan
            - output
    l3_interface_action:
        primitives:
            - set_vid
            - set_eth_src
            - set_eth_dst
            - dec_ttl
            - output
    l3_bridged_interface_action:
        primitives:
            - set_vid
            - set_eth_src
            - set_eth_dst
            - dec_ttl
tables:
    eth_dst:
        matches:
            hdr.ethernet.destination: exact
            hdr.vlan.vid: exact
        actions:
            - drop_action
            - l2_tagged_interface_action
            - l2_untagged_interface_action
    ipv4:
        matches:
            istd.ingress_port: exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: exact
            hdr.ipv4.destination: exact
        actions:
            - drop_action
            - l3_interface_action
            - l3_bridged_interface_action
    ipv4_source:
        matches:
            istd.ingress_port: all_or_exact
            istd.ethertype: all_or_exact
            hdr.vlan.vid: all_or_exact
            hdr.ipv4.source: ternary
        actions:
            - drop_action
    ipv4_lpm:
        matches:
            istd.ingress_port: exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: exact
            hdr.ipv4.destination: exact
        actions:
            - drop_action
            - l3_interface_action
            - l3_bridged_interface_action
    ipv6:
        matches:
            istd.ingress_port: exact
            hdr.vlan.vid: exact
            hdr.ipv6.source: exact
            hdr.ipv6.destination: exact
        actions:
            - drop_action
            - l3_interface_action
            - l3_bridged_interface_action
    ternary_l4:
        matches:
            istd.ip_proto: exact
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
    ternary_port:
        matches:
            istd.ingress_port: ternary
        actions:
            - drop_action
    ternary_ipv4:
        matches:
            hdr.ipv4.source: ternary
            hdr.ipv4.destination: ternary
        actions:
            - drop_action
            - l3_interface_action
    ternary_ipv6:
        matches:
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
        actions:
            - drop_action
            - l3_interface_action
    tcp_filter:
        matches:
            hdr.tcp.source: all_or_exact
            hdr.tcp.destination: all_or_exact
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
        actions:
            - drop_action
            - l2_tagged_interface_action
            - l2_untagged_interface_action
    udp_filter:
        matches:
            hdr.udp.source: all_or_exact
            hdr.udp.destination: all_or_exact
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
        actions:
            - drop_action
            - l2_tagged_interface_action
            - l2_untagged_interface_action
pipeline:
{module}
"""

    HW_TEMPLATE = """
actions:
    drop_action:
        primitives:
            - mark_to_drop
    notify_action:
        primitives:
            - notify
    output_action:
        primitives:
            - output
    pop_vlan_action:
        primitives:
            - pop_vlan
    l2_rewrite_action:
        primitives:
            - set_vid
            - set_eth_src
            - set_eth_dst
    dec_ttl_action:
        primitives:
            - dec_ttl
    goto_action:
        primitives:
            - goto
tables:
    eth_dst:
        matches:
            hdr.vlan.vid: exact
            hdr.ethernet.destination: exact
        actions:
            - drop_action
            - pop_vlan_action
            - output_action
    eth_dst_recirc:
        matches:
            hdr.vlan.vid: exact
            hdr.ethernet.destination: exact
            istd.recirculation: exact
        actions:
            - drop_action
            - pop_vlan_action
            - output_action
    ipv4:
        matches:
            istd.ingress_port: configured_exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - output_action
    ipv4_recirc:
        matches:
            istd.ingress_port: configured_exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
            istd.recirculation: configured_any
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - output_action
    ipv4_source:
        matches:
            istd.ingress_port: all_or_exact
            istd.ethertype: all_or_exact
            hdr.vlan.vid: all_or_exact
            hdr.ipv4.source: ternary
        actions:
            - drop_action
    ipv4_missing_actions:
        matches:
            istd.ingress_port: exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - output_action
    ethertype_ipv4:
        matches:
            istd.ingress_port: exact
            istd.ethertype: exact
            hdr.vlan.vid: exact
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - output_action
    ternary_ipv4:
        matches:
            hdr.ipv4.source: ternary
            hdr.ipv4.destination: ternary
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - output_action
    ternary_ipv6:
        matches:
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - output_action
    ternary_5tuple:
        matches:
            istd.ip_proto: exact
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - pop_vlan_action
            - output_action
    ternary_5tuple_recirc:
        matches:
            istd.recirculation: ternary
            istd.ip_proto: all_or_exact
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - pop_vlan_action
            - output_action
    ternary_5tuple_ethertype:
        matches:
            istd.ethertype: exact
            istd.ip_proto: exact
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - pop_vlan_action
            - output_action
    ternary_l4:
        matches:
            istd.ip_proto: exact
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
    ternary_tcp:
        matches:
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
        actions:
            - drop_action
    ternary_ipv6_tcp_no_ip_proto:
        matches:
            hdr.ipv6.source: ternary
            hdr.ipv6.destination: ternary
            hdr.tcp.source: ternary
            hdr.tcp.destination: ternary
        actions:
            - drop_action
            - pop_vlan_action
            - output_action
    ternary_udp:
        matches:
            hdr.udp.source: ternary
            hdr.udp.destination: ternary
        actions:
            - drop_action
    goto_table:
        matches:
            istd.ingress_port: configured_any
            istd.ethertype: configured_any
            istd.ip_proto: configured_any
            hdr.ethernet.source: configured_any
            hdr.ethernet.destination: configured_any
            hdr.vlan.vid: configured_any
            hdr.ipv6.source: configured_any
            hdr.ipv6.destination: configured_any
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - goto_action
    target_table:
        matches:
            istd.ingress_port: configured_any
            istd.ethertype: configured_any
            istd.ip_proto: configured_any
            hdr.ethernet.source: configured_any
            hdr.ethernet.destination: configured_any
            hdr.vlan.vid: configured_any
            hdr.ipv6.source: configured_any
            hdr.ipv6.destination: configured_any
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - pop_vlan_action
            - output_action
            - goto_action
    target_table_2:
        matches:
            istd.ingress_port: configured_any
            istd.ethertype: configured_any
            istd.ip_proto: configured_any
            hdr.ethernet.source: configured_any
            hdr.ethernet.destination: configured_any
            hdr.vlan.vid: configured_any
            hdr.ipv6.source: configured_any
            hdr.ipv6.destination: configured_any
            hdr.ipv4.source: configured_any
            hdr.ipv4.destination: configured_any
        actions:
            - drop_action
            - l2_rewrite_action
            - dec_ttl_action
            - pop_vlan_action
            - output_action
pipeline:
{module}
"""

    def setup_pipelines(self, hw_modules, sw_modules):
        self.hw_pipeline = yml_transform.Pipeline(
            'hw_pipeline', yaml.safe_load(self.HW_TEMPLATE.format(module=hw_modules)))
        self.sw_pipeline = yml_transform.Pipeline(
            'sw_pipeline', yaml.safe_load(self.SW_TEMPLATE.format(module=sw_modules)))

    def setup_module_map(self, hw_modules, sw_modules):
        self.setup_pipelines(hw_modules, sw_modules)
        self.module_map = yml_transform.ModuleMap(
            self.hw_pipeline.action_modules[0], self.sw_pipeline.action_modules[0], None)

    def tearDown(self):
        logging.disable(logging.DEBUG)
        logging.disable(logging.INFO)

    def test_load_pipelines(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        self.setup_pipelines(hw_modules, sw_modules)

    def test_potential_maps(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4
        - type: table
          table: ipv6"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.assertIn('ipv4', self.module_map.get_potential_map('ipv4'))
        self.assertFalse('ipv6' in self.module_map.get_potential_map('ipv4'))

    def test_potential_map_missing_actions(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_missing_actions"""
        self.setup_module_map(hw_modules, sw_modules)
        self.assertFalse('ipv4' in self.module_map.get_potential_map('ipv4'))

    #def test_potential_ternary_concatenate_merge(self):
    #    sw_modules = """
    #- test_module:
    #    - type: table
    #      table: ternary_l4
    #      iffalse:
    #        - type: table
    #          table: ternary_ipv4"""
    #    hw_modules = """
    #- test_module:
    #    - type: table
    #      table: ipv4_missing_actions"""
    #    self.setup_module_map(hw_modules, sw_modules)
    #    self.assertIn(
    #        'ternary_ipv4', self.module_map.get_mergeable_tables('ternary_l4'))

    def test_potential_ternary_mutually_exclusive_merge(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_missing_actions"""
        self.setup_module_map(hw_modules, sw_modules)
        self.assertIn(
            'ternary_ipv4', self.module_map.get_mergeable_tables('ternary_ipv6'))

    def test_potential_action_merge(self):
        sw_modules = """
    - test_module:
          - type: table
            table: ternary_l4
          - type: table
            table: ternary_port"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_missing_actions"""
        self.setup_module_map(hw_modules, sw_modules)
        self.assertIn(
            'ternary_port', self.module_map.get_mergeable_tables('ternary_l4'))

    def test_contradiction(self):
        sw_modules = """
    - test_module:
          - type: table
            table: ipv4
          - type: table
            table: ipv6"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_missing_actions"""
        self.setup_module_map(hw_modules, sw_modules)
        self.assertFalse(
            'ipv4' in self.module_map.get_mergeable_tables('ipv6'))
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_trivial_map(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_trivial_conditional_map(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_trivial_table_condition_map(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4_source
          iftrue:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_source
          iftrue:
            - type: table
              table: ternary_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_trivial_conditional_to_table_map(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ipv4_source
          iftrue:
            - type: table
              table: ternary_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_mutually_exclusive_merge(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ip_proto
          value: 0x6
          iftrue:
            - type: table
              table: tcp_filter
          iffalse:
            - type: conditional
              field: istd.ip_proto
              value: 0x11
              iftrue:
                - type: table
                  table: udp_filter"""
        hw_modules = """
    - test_module:
        - type: table
          table: ternary_5tuple"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertIn('tcp_filter', self.module_map.get_potential_map('ternary_5tuple'))
        self.assertIn('udp_filter', self.module_map.get_potential_map('ternary_5tuple'))
        self.assertIn(
            'tcp_filter', self.module_map.get_mergeable_tables('udp_filter'))
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_conditional_merge(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ip_proto
          value: 0x6
          iftrue:
            - type: table
              table: ternary_ipv6
        """
        hw_modules = """
    - test_module:
        - type: table
          table: ternary_5tuple"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_concatenate_merge(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ip_proto
          value: 0x6
          iftrue:
            - type: table
              table: tcp_filter
              iffalse:
                  - type: table
                    table: ternary_ipv6"""
        hw_modules = """
    - test_module:
        - type: table
          table: ternary_5tuple"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_excess_match(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ethertype_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_bad_table_condition(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ipv4_source
          iftrue:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module:
        - type: table
          table: ternary_ipv4
          iftrue:
            - type: table
              table: ipv4_source"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_bad_conditional(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x800
          iftrue:
            - type: table
              table: ternary_ipv4
          iffalse:
            - type: table
              table: ternary_ipv6"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_excess_conditional(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ternary_l4"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ip_proto
          value: 0x6
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_excess_matches(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ternary_ipv6
        """
        hw_modules = """
    - test_module:
        - type: table
          table: ternary_5tuple"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertFalse(self.module_map.get_complete_cmaps())

    def test_conditional_chain(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: conditional
              field: istd.ip_proto
              value: 0x6
              iftrue:
                  - type: table
                    table: tcp_filter"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ip_proto
          value: 0x6
          iftrue:
            - type: conditional
              field: istd.ethertype
              value: 0x86DD
              iftrue:
                  - type: table
                    table: ternary_ipv6_tcp_no_ip_proto"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_two_children_trivial(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
            - type: table
              table: ternary_l4"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
            - type: table
              table: ternary_l4"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())


    def test_two_children_separated(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
            - type: table
              table: ternary_l4"""
        hw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
        - type: table
          table: ternary_5tuple_ethertype"""
        self.setup_module_map(hw_modules, sw_modules)
        self.module_map.map()
        self.assertTrue(self.module_map.get_complete_cmaps())

    def test_multiple_modules(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ternary_l4
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ternary_l4
    - test_module_2:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_multiple_modules_redundant_module(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ternary_l4
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ternary_ipv4
    - test_module_2:
        - type: table
          table: ternary_l4
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_multiple_modules_bad_path(self):
        sw_modules = """
    - test_module:
        - type: table
          table: ternary_l4
          iftrue:
            - type: conditional
              field: istd.ethertype
              value: 0x86DD
              iftrue:
                - type: table
                  table: ternary_ipv6"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ternary_l4
    - test_module_2:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertFalse(self.hw_pipeline.map(self.sw_pipeline))

    def test_multiple_software_modules(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: ternary_l4
    - test_module_2:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ternary_l4
    - test_module_2:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_trivial_goto(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv4"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: goto_table
    - test_module_2:
        - type: target
          name: target_table_target
          iftrue:
            - type: table
              table: target_table
            """
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_goto_iffalse(self):
        logging.disable(logging.NOTSET)
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv6
          iffalse:
            - type: table
              table: ternary_ipv4
        """
        hw_modules = """
    - test_module_1:
        - type: table
          table: goto_table
    - test_module_2:
        - type: target
          name: target_table_target
          iftrue:
            - type: table
              table: target_table
    - test_module_3:
        - type: target
          name: target_table_2_target
          iftrue:
            - type: table
              table: target_table_2
            """
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_complex_goto(self):
        sw_modules = """
    - test_module:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: ternary_ipv4
        - type: table
          table: ternary_port
        """
        hw_modules = """
    - test_module_1:
        - type: table
          table: goto_table
    - test_module_2:
        - type: target
          name: target_table_target
          iftrue:
            - type: table
              table: target_table
    - test_module_3:
        - type: target
          name: target_table_2_target
          iftrue:
            - type: table
              table: target_table_2
            """
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_trivial_recirculate(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: ipv4_lpm
    - test_module_2:
        - type: table
          table: eth_dst"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ipv4_recirc
        - type: table
          table: eth_dst_recirc"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_no_recirc_meta(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: ipv4_lpm
    - test_module_2:
        - type: table
          table: eth_dst"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ipv4
        - type: table
          table: eth_dst"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertFalse(self.hw_pipeline.map(self.sw_pipeline))

    def test_trivial_recirculate(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: ipv4_lpm
    - test_module_2:
        - type: table
          table: eth_dst"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ipv4_recirc
        - type: table
          table: eth_dst_recirc"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_recirculation_merge(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: ternary_l4
    - test_module_2:
        - type: table
          table: ternary_ipv6"""
        hw_modules = """
    - test_module_1:
        - type: table
          table: ternary_5tuple_recirc"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertTrue(self.hw_pipeline.map(self.sw_pipeline))

    def test_excess_conditional(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: eth_dst"""
        hw_modules = """
    - test_module_1:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iftrue:
            - type: table
              table: eth_dst"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertFalse(self.hw_pipeline.map(self.sw_pipeline))

    def test_excess_false_conditional(self):
        sw_modules = """
    - test_module_1:
        - type: table
          table: eth_dst"""
        hw_modules = """
    - test_module_1:
        - type: conditional
          field: istd.ethertype
          value: 0x86DD
          iffalse:
            - type: table
              table: eth_dst"""
        self.setup_pipelines(hw_modules, sw_modules)
        self.assertFalse(self.hw_pipeline.map(self.sw_pipeline))
