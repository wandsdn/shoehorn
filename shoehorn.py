import copy
import logging

logger = logging.getLogger(__name__)

class Action:
    PRIMITIVE_ACTIONS = set((
        'notify', 'clone', 'output', 'dec_ttl', 'copy_ttl_in', 'multicast',
        'push_vlan', 'pop_vlan', 'set_eth_dst', 'set_eth_src', 'set_vid',
        'set_vrf', 'mark_to_drop', 'goto', 'pop_mpls', 'set_mpls_label',
        'push_mpls', 'set_ipv4_src', 'set_ipv4_dst', 'set_udp_src', 'set_udp_dst'))

    def __init__(self, name, data):
        self.name = name
        self.primitives = set(data.get('primitives', []))
        assert self.primitives.issubset(
            self.PRIMITIVE_ACTIONS), f"bad primitives {self.primitives}"

    def is_action_mergeable(self):
        return self.primitives.issubset({'notify', 'mark_to_drop'})

    def is_goto(self):
        return 'goto' in self.primitives

    def is_noop(self):
        return not self.primitives or self.primitives == set('NoAction')

    def __eq__(self, other):
        return self.primitives == other.primitives and self.name == other.name

    def __hash__(self):
        return hash((self.name, tuple(sorted(self.primitives))))

    def __repr__(self):
        return f"{self.name} {self.primitives}"

class Match:
    TERNARY = 'ternary'
    LPM = 'lpm'
    EXACT = 'exact'
    ALL_OR_EXACT = 'all_or_exact'
    CNF_TERNARY = 'configured_ternary'
    CNF_LPM = 'configured_lpm'
    CNF_EXACT = 'configured_exact'
    CNF_ALL_OR_EXACT = 'configured_all_or_exact'
    CNF_ANY = 'configured_any'
    FULL_SUPPORT = "FULL"
    PARTIAL_SUPPORT = "PARTIAL"
    FIELDS = set(('hdr.ethernet.destination', 'hdr.ethernet.source',
              'hdr.ethernet.type', 'hdr.vlan.vid', 'hdr.vlan.pcp',
              'hdr.vlan.dei', 'hdr.mpls.label', 'hdr.mpls.bos',
              'hdr.ipv4.dscp', 'hdr.ipv4.ecn', 'hdr.ipv4.proto',
              'hdr.ipv4.source', 'hdr.ipv4.destination', 'hdr.ipv6.dscp',
              'hdr.ipv6.ecn', 'hdr.ipv6.source', 'hdr.ipv6.destination',
              'hdr.ipv6.flow_label', 'hdr.tcp.source', 'hdr.tcp.destination',
              'hdr.udp.source', 'hdr.udp.destination', 'hdr.arp.oper',
              'hdr.arp.spa', 'hdr.arp.tpa', 'hdr.arp.sha', 'hdr.arp.tha',
              'istd.ingress_port', 'istd.egress_spec', 'istd.multicast_spec',
              'istd.egress_port', 'istd.instance_type', 'istd.packet_length',
              'istd.is_tagged', 'istd.ethertype', 'istd.ip_proto', 'istd.vrf',
              'istd.recirculation', 'istd.l4_source', 'istd.l4_destination'))

    MATCH_KINDS = set((TERNARY, LPM, EXACT, ALL_OR_EXACT, CNF_TERNARY, CNF_LPM,
        CNF_EXACT, CNF_ALL_OR_EXACT, CNF_ANY))

    def __init__(self, field, match_kind):
        self.field = field
        self.match_kind = match_kind
        assert self.field in self.FIELDS, f"invalid field: {self.field}"
        assert self.match_kind in self.MATCH_KINDS, self.match_kind

    def convert_constant(self, constant):
        CONSTANTS = {
            "TPID_VLAN": ByteVal(value=0x8100, base=16),
            "TYPE_IPV4": ByteVal(value=0x800, base=16),
            "TYPE_IPV6": ByteVal(value=0x86DD, base=16),
            "TYPE_ARP": ByteVal(value=0x806, base=16),
            "IP_PROTO_ICMP": ByteVal(value=0x1, base=8),
            "IP_PROTO_TCP": ByteVal(value=0x6, base=8),
            "IP_PROTO_UDP": ByteVal(value=0x11, base=8),
            }
        return CONSTANTS[constant]

    def supports(self, sw_match):
        if self.field != sw_match.field:
            return None

        # TODO: currently not allowing configured matches in sw code. Consider whether
        # this is needed
        SUPPORTING_KINDS = {
            Match.EXACT: set([
                Match.ALL_OR_EXACT, Match.CNF_EXACT, Match.EXACT, Match.CNF_ANY]),
            Match.ALL_OR_EXACT: set([
                Match.ALL_OR_EXACT, Match.CNF_EXACT, Match.CNF_ANY,
                Match.TERNARY, Match.CNF_TERNARY]),
            Match.LPM: set([Match.LPM, Match.CNF_ANY]),
            Match.TERNARY: set([Match.TERNARY, Match.CNF_TERNARY, Match.CNF_ANY]),
            }
        PARTIAL_SUPPORTING_KINDS = {
            Match.EXACT: set([Match.TERNARY, Match.CNF_TERNARY, Match.LPM]),
            Match.ALL_OR_EXACT: set([]),
            Match.LPM: set([Match.TERNARY, Match.CNF_TERNARY]),
            Match.TERNARY: set([]),
            }
        if self.match_kind in SUPPORTING_KINDS[sw_match.match_kind]:
            return self.FULL_SUPPORT
        if self.match_kind in PARTIAL_SUPPORTING_KINDS[sw_match.match_kind]:
            return self.PARTIAL_SUPPORT
        return None

    def is_maskable(self):
        return self.match_kind in (
            Match.TERNARY, Match.CNF_TERNARY, Match.CNF_ANY)

    def is_optional(self):
        return self.is_maskable or self.match_kind in (
            Match.ALL_OR_EXACT, Match.CNF_ALL_OR_EXACT, Match.CNF_EXACT,
            Match.CNF_LPM)

    def __eq__(self, other):
        return self.field == other.field and self.match_kind == other.match_kind

    def __hash__(self):
        return hash((self.field, self.match_kind))

    def __repr__(self):
        return f"{self.field}: {self.match_kind}"

class PathElement:
    def __init__(self, component, outcome, is_table):
        self.component = component
        self.outcome = outcome
        self.is_table = is_table

    def __hash__(self):
        return hash((self.component, self.outcome))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __repr__(self):
        return repr((self.component, self.outcome))

class Component:
    def __init__(self, name):
        self.name = name
        self.iftrue = {}
        self.iffalse = {}
        self.annotations = []
        self.actions = set()
        self.path = []

    def __repr__(self):
        match_names = [m.field for m in self.get_matches()]
        action_names = [a.name for a in self.get_actions()]
        return f"{self.name}|{match_names}|{action_names}|{self.annotations}"

    def is_descendant(self, other):
        for path_element in self.path:
            if path_element.component == other.name:
                return True
        return False

    def is_ancestor(self, other):
        return other.is_descendant(self)

    def is_mutually_exclusive(self, other):
        common_ancestor = self.find_common_ancestor(other)
        if common_ancestor is None or common_ancestor == self\
        or common_ancestor == other:
            return False
        for i, path_element in enumerate(self.path):
            if common_ancestor == path_element.component:
                # outcome for common ancestor must be different
                return path_element.outcome != other.path[i].outcome

    def find_common_ancestor(self, other):
        logger.debug(f"find common ancestor between {self} and {other}")
        result = None
        if self.is_descendant(other):
            result = self.name
        elif self.is_ancestor(other):
            result = other.name
        else:
            for i, path_element in enumerate(self.path):
                if len(other.path) <= i:
                    break
                elif path_element == other.path[i]:
                    result = path_element.component
                elif path_element.component == other.path[i].component:
                    result = path_element.component
                    break
                else:
                    break
        return result

    def get_matches(self):
        return set()

    def get_match_by_field(self, field):
        return None

    def get_actions(self):
        return set()

    def is_action_mergeable(self):
        return all(a.is_action_mergeable() for a in self.get_actions())

    def add_iftrue(self, components):
        self.iftrue = components

    def add_iffalse(self, components):
        self.iffalse = components

    def is_goto(self):
        # True only if component is a Table
        return False

    def is_noop(self):
        for action in self.actions:
            if not action.is_noop():
                return False
        return True

    def base_match_kind(self):
        match_kinds = {m.match_kind for m in self.get_matches()}
        if Match.TERNARY in match_kinds or Match.ALL_OR_EXACT in match_kinds:
            return Match.TERNARY
        if Match.LPM in match_kinds:
            return Match.LPM
        return Match.EXACT

    def flexible_match_kinds(self):
        return 'flexible_match_kinds' in self.annotations\
            or self.base_match_kind() == Match.TERNARY

    def flexible_mapping(self):
        return 'flexible_mapping' in self.annotations

    def supports_actions(self, sw_component):
        # I am looking for a combination of actions that combine to cover all
        # the action primitives for each sw_table action
        for sw_action in sw_component.actions:
            sw_primitives = copy.copy(sw_action.primitives)
            for hw_action in self.actions:
                if not hw_action.primitives.issubset(sw_action.primitives):
                    # in this case the hw_action requires actions the sw_action
                    # doesnt want
                    continue
                sw_primitives = sw_primitives - hw_action.primitives
                if not sw_primitives:
                    break
            if sw_primitives:
                logger.debug(f"unsupported action primitives: {sw_primitives}")
                return False
        return True

    def can_merge(self, other):
        result = True
        if isinstance(other, Table):
            # merging is complicated for tables, so always try to merge into
            # the table
            result = other.can_merge(self)
        elif isinstance(other, Component):
            result = self.is_mutually_exclusive(other)\
                or self.is_descendant(other) or other.is_descendant(self)
        else:
            raise TypeError()
        return result

    def supports(self, other):
        # supports indicates the component is supportable abstract from the
        # pipeline. It also ignores excess matches as these may be supportable
        # in context
        raise NotImplementedError

class Table(Component):
    def __init__(self, name, data, actions):
        super().__init__(name)
        self.matches = set()
        self.matches_by_field = {}
        annotations = data.get('annotations', [])
        self.actions = set(actions[a] for a in data.get('actions', []))
        for name, kind in data.get('matches', {}).items():
            match = Match(name, kind)
            self.matches.add(match)
            self.matches_by_field[match.field] = match

    def get_match_by_field(self, field):
        return self.matches_by_field.get(field)

    def get_matches(self):
        return self.matches

    def get_actions(self):
        return self.actions

    def supports_matches(self, sw_table):
        for sw_match in sw_table.matches:
            unsupported = True
            for hw_match in self.matches:
                support = hw_match.supports(sw_match)
                if not support:
                    continue
                if support == Match.FULL_SUPPORT or sw_table.flexible_mapping():
                    unsupported = False
                    break
            if unsupported:
                logger.debug(f"Table: {sw_match} is unsupported")
                return False
        return True

    def is_goto(self):
        return any(a.is_goto() for a in self.actions)

    def supports(self, sw_component):
        # this indicates it is possible for this table to support the
        # sw_component
        # we do not check for excess matches because that could be supported
        # based on where these are in the pipeline, we are only looking if it
        # is possible in principle for this hardware component to support this
        # software component
        result = False
        logger.debug(f"Table: checking if {self.name} supports {sw_component.name}")

        if isinstance(sw_component, Table):
            result = self.supports_matches(sw_component)\
                and self.supports_actions(sw_component)
        elif isinstance(sw_component, Conditional):
            for match in self.matches:
                if match.field != sw_component.field:
                    continue
                if sw_component.mask:
                    # TODO: check for lpm masks
                    result = match.is_maskable()
                else:
                    result = True
        else:
            raise TypeError
        return result

    def can_ternary_concatenate(self, other):
        result = False
        if not self.flexible_match_kinds():
            return result
        if not other.flexible_match_kinds():
            return result
        if self.is_ancestor(other):
            ancestor = self
            descendant = other
        elif other.is_ancestor(self):
            descendant = self
            ancestor = other
        else:
            return result
        for path_element in descendant.path:
            if path_element.component == ancestor:
                # Can only concatenate on a miss
                result = not path_element.outcome
                break
        return result

    def can_mutually_exclusive_merge(self, other):
        if not (self.flexible_match_kinds() and other.flexible_match_kinds()):
            return False
        return self.is_mutually_exclusive(other)

    def can_action_merge(self, other):
        # ok lets say t1 is an ancestor of t2. But they just do the same actions
        # Would we need a cross product? Why would this situation exist? It makes no
        # sense. Lets just assume in this case that it doesnt matter
        return self.is_action_mergeable() and other.is_action_mergeable()

    def can_merge(self, other):
        result = False
        if isinstance(other, Conditional):
            result = self.is_descendant(other) or self.is_mutually_exclusive(other)
        else:
            result = self.can_ternary_concatenate(other)\
                or self.can_mutually_exclusive_merge(other)\
                or self.can_action_merge(other)
        return result

class Target(Component):
    def __init__(self, name, goto_tables):
        super().__init__(name)
        self.goto_tables = goto_tables
        self.iftrue = {}
        self.path = []
        self.first_goto = None

    def get_hw_component_name(self):
        return self.first_goto

    def supports(self, sw_component):
        return any((t.supports(sw_component) for t in self.goto_tables))

    def add_child(self, component, outcome):
        assert outcome, "Target should never have iffalse"
        self.iftrue[component.name] = component

    def clone(self):
        result = Target(self.name, copy.copy(self.goto_tables))
        result.path = copy.copy(self.path)
        for name, child in self.iftrue.items():
            result.iftrue[name] = child.clone()
        return result

    def get_children(self, recursive=False):
        result = []
        for child in self.iftrue.values():
            result.append(child)
            if recursive:
                result.extend(child.get_children(recursive))
        return result

    def resolve_gotos(self, next_goto):
        if self.first_goto:
            return
        for child in self.iftrue.values():
            if self.first_goto is None:
                self.first_goto = child.get_hw_component_name()
            child.resolve_gotos(next_goto)
            next_goto = child.get_hw_component_name()

    def to_json_data(self, recirculation):
        return {}

class Conditional(Component):
    _count = 0

    def __init__(self, field, value, mask):
        super().__init__(f"conditional_{Conditional._count}-{field}-0x{value:x}/{mask}")
        Conditional._count += 1
        self.field = field
        self.value = value
        self.mask = mask
        match_kind = Match.EXACT
        if mask is not None:
            match_kind = Match.TERNARY
        self.match = Match(self.field, match_kind)
        # conditionals can always be mapped flexibly
        self.annotations = ['flexible_mapping', 'flexible_match_kinds']

    def get_match_by_field(self, field):
        if field != field:
            return None
        return self.match

    def get_matches(self):
        return set([self.match])

    def base_match_kind(self):
        # conditionals are always flexible, so the base match kind is always
        # ternary
        return Match.TERNARY

    def supports(self, sw_component):
        if not isinstance(sw_component, Conditional):
            return False
        return self.field == sw_component.field\
            and self.value == sw_component.value\
            and self.mask == sw_component.mask

class PathError(ValueError):
    pass

class EntryTree:
    def __init__(self, component):
        self.component = component
        self.iftrue = None
        self.iffalse = None
        self.true_goto = None
        self.false_goto = None

    def to_json_data(self, prefix):
        result = []
        if prefix:
            prefix = f"{prefix} & {self.component.name}"
        else:
            prefix = self.component.name
        if self.iftrue:
            result = self.iftrue.to_json_data(prefix)
        else:
            if self.true_goto:
                goto = self.true_goto.get_hw_component_name()
            else:
                goto = None
            result.append({prefix: goto})
        if self.iffalse:
            result.extend(self.iffalse.to_json_data(prefix))
        elif not prefix:
            if self.false_goto:
                goto = self.false_goto.hw_component.name
            else:
                goto = None
            result.extend({'default': goto})
        return result

    def resolve_gotos(self, true_goto, false_goto):
        # ok the later in the tree structure you appear the earlier you get
        # added
        # resolve gotos when they appear, passing in the earlier appearing
        # components as the subsequent gotos
        next_true_goto = true_goto
        if self.true_goto:
            next_true_goto = self.true_goto
        next_false_goto = false_goto
        if self.false_goto:
            next_false_goto = self.false_goto

        if self.iftrue:
            if self.true_goto:
                self.iftrue.resolve_gotos(self.true_goto, self.true_goto)
                self.true_goto.resolve_gotos(true_goto)
                # ok the true_goto here is passed down, so I can set it to None here
                self.true_goto = None
            else:
                self.iftrue.resolve_gotos(true_goto, true_goto)
        elif self.true_goto:
            # TODO: this should be iterable
            self.true_goto.resolve_gotos(true_goto)
        else:
            # dont need to resolve this, it will be done where it originates
            self.true_goto = true_goto

        if self.iffalse:
            if self.false_goto:
                next_true_goto = true_goto
                if self.true_goto:
                    next_true_goto = self.true_goto
                self.iffalse.resolve_gotos(next_true_goto, self.false_goto)
                self.false_goto.resolve_gotos(false_goto)
                self.false_goto = None
            else:
                self.iffalse.resolve_gotos(true_goto, false_goto)
        elif self.false_goto:
            self.false_goto.resolve_gotos(false_goto)
        else:
            self.false_goto = false_goto

    def get_children(self, recursive=False):
        result = []
        if self.true_goto:
            result.append(true_goto)
            if recursive:
                result.extend(true_goto.get_children(recursive))
        if self.false_goto:
            result.append(false_goto)
            if recursive:
                result.extend(false_goto.get_children(recursive))
        if self.iftrue:
            result.extend(self.iftrue.get_children(recursive))
        if self.iffalse:
            result.extend(self.iffalse.get_children(recursive))
        return result

    def set_goto(self, child):
        final_pe = child.entry_tree.path[-1]
        if final_pe.component == self.component.name:
            if final_pe.outcome == True:
                self.true_goto = child.target
            else:
                self.false_goto = child.target
        for pe in child.path:
            # TODO: you could get an attribute error here, if you set_goto
            # incorrectly somewhere
            if pe.component != self.component.name:
                continue
            if pe.outcome:
                self.iftrue.set_goto(child)
            else:
                self.iffalse.set_goto(child)

    def get_matches(self):
        result = set()
        matches = {m.field: m for m in self.component.get_matches()}
        if self.iftrue:
            # TODO: there is potentially a bug here if you have a chain of like
            # if ip address starts with a 1 and then in the next table have
            # if ip address is 1.1.1.1 like, this could get messy, but it seems
            # unlikely
            matches.update({m.field: m for m in self.iftrue.get_matches()})
        if self.iffalse:
            new_matches = {}
            for match in self.iffalse.get_matches():
                true_match = matches.pop(match.field, None)
                new_matches[match.field] = self.combine_matches(true_match, match)
            for match in matches.values():
                new_matches[match.field] = self.combine_matches(match, None)
            matches = new_matches
        result = set(matches.values())
        return result

    def combine_matches(self, high_match, low_match):
        result = None
        if high_match is None:
            if low_match.match_kind == Match.EXACT:
                result = Match(low_match.field, Match.ALL_OR_EXACT)
            else:
                result = low_match
        elif low_match is None:
            if high_match.match_kind == Match.EXACT:
                result = Match(high_match.field, Match.ALL_OR_EXACT)
            else:
                result = high_match
        elif high_match == low_match and high_match.match_kind != Match.LPM:
            result = high_match
        elif high_match.match_kind == Match.TERNARY:
            result = high_match
        elif low_match.match_kind == Match.TERNARY:
            result = low_match
        elif high_match.match_kind == Match.EXACT and low_match.match_kind == Match.LPM:
            result = low_match
        elif Match.LPM in (high_match.match_kind, low_match.match_kind):
            result = Match(high_match.field, Match.TERNARY)
        elif high_match.match_kind == Match.ALL_OR_EXACT or low_match.match_kind is None:
            result = high_match
        elif low_match.match_kind == Match.ALL_OR_EXACT or low_match.match_kind is None:
            result = low_match
        else:
            raise ValueError(
                f"weird match kinds {high_match.match_kind} & {low_match.match_kind}")
        return result

    def get_path(self):
        true_path = None
        false_path = None
        if self.iftrue:
            true_path = self.iftrue.get_path()
        if self.iffalse:
            false_path = self.iffalse.get_path()
        else:
            if isinstance(self.component, Table):
                return self.component.path
            else:
                return None

        if true_path is not None:
            true_path = [e for e in true_path if e.component != self.component.name]
            if set(true_path) != set(self.component.path):
                raise PathError("Inconsistent paths in entry tree")
        if false_path is not None:
            false_path = [e for e in false_path if e.component != self.component.name]
            if set(false_path) != set(self.component.path):
                raise PathError("Inconsistent paths in entry tree")

        return self.component.path

    def can_merge(self, et):
        return self.merge(et, apply_change=False)

    def merge(self, et, apply_change=True):
        result = False
        for path_element in et.component.path:
            if path_element.component == self.component.name:
                if path_element.outcome:
                    if self.iftrue:
                        result = self.iftrue.merge(et, apply_change)
                    elif isinstance(self.component, Table):
                        # no table cross products. This is a noop, but just
                        # being explicit here
                        result = False
                    else:
                        result = True
                        if apply_change:
                            self.iftrue = et
                else:
                    if self.iffalse:
                        result = self.iffalse.merge(et, apply_change)
                    else:
                        result = True
                        if apply_change:
                            self.iffalse = et
                break
        return result

    def base_match_kind(self):
        match_kinds = {m.match_kind for m in self.get_matches()}
        if Match.TERNARY in match_kinds or Match.ALL_OR_EXACT in match_kinds:
            return Match.TERNARY
        if Match.LPM in match_kinds:
            return Match.LPM
        return Match.EXACT

    def get_components(self):
        yield self.component
        if self.iftrue:
            for component in self.iftrue.get_components():
                yield component
        if self.iffalse:
            for component in self.iffalse.get_components():
                yield component

    def clone(self):
        result = EntryTree(self.component)
        if self.iftrue:
            result.iftrue = self.iftrue.clone()
        if self.iffalse:
            result.iffalse = self.iffalse.clone()
        result.true_goto = self.true_goto
        result.false_goto = self.false_goto
        return result


class MappedComponent(Component):
    _count = 0
    def __init__(self, hw_component, path, target, name=None):
        if name:
            super().__init__(name)
        else:
            super().__init__(f"mapped_component_{MappedComponent._count}")
            MappedComponent._count += 1
        self.hw_component = hw_component
        self.entry_trees = [None]
        self.path = path
        self.target = target
        self.annotations = []
        self.iftrue = {}
        self.iffalse = {}

    def get_hw_component_name(self):
        return self.hw_component.name

    def to_json_data(self, recirculation):
        result = {}
        data = []
        if len(self.entry_trees) > recirculation and self.entry_trees[recirculation]:
            data = self.entry_trees[recirculation].to_json_data('')
        if data:
            result[self.hw_component.name] = data
        else:
            result[self.hw_component.name] = None
        return result

    def resolve_gotos(self, goto):
        iftrue_components = list(self.iftrue.values())
        true_goto = goto
        if iftrue_components:
            true_goto = iftrue_components[0]
        iffalse_components = list(self.iffalse.values())
        false_goto = goto
        if iffalse_components:
            false_goto = iffalse_components[0]
        # now I iterate through the entry tree
        # I follow the gotos there
        for entry_tree in self.entry_trees:
            if entry_tree is None:
                continue
            entry_tree.resolve_gotos(true_goto, false_goto)


    def recirculate(self):
        self.entry_trees.append(None)

    def clone(self):
        result = MappedComponent(self.hw_component, self.path, self.target, self.name)
        result.entry_trees = []
        for entry_tree in self.entry_trees:
            if entry_tree is None:
                result.entry_trees.append(None)
            else:
                result.entry_trees.append(entry_tree.clone())
        entry_trees = copy.copy(result.entry_trees)
        while entry_trees:
            entry_tree = entry_trees.pop()
            if entry_tree is None:
                continue
            if entry_tree.true_goto:
                entry_tree.true_goto = entry_tree.true_goto.clone()
            if entry_tree.false_goto:
                entry_tree.false_goto = entry_tree.false_goto.clone()
            entry_trees.append(entry_tree.iftrue)
            entry_trees.append(entry_tree.iffalse)

        for name, child in self.iftrue.items():
            result.iftrue[name] = child.clone()
        for name, child in self.iffalse.items():
            result.iffalse[name] = child.clone()
        return result

    def add_child(self, child, iftrue):
        if iftrue:
            self.iftrue[child.name] = child
        else:
            self.iffalse[child.name] = child

    def get_children(self, recursive=False):
        result = []
        for child in self.iftrue.values():
            result.append(child)
            if recursive:
                result.extend(child.get_children(recursive))
        for child in self.iffalse.values():
            result.append(child)
            if recursive:
                result.extend(child.get_children(recursive))
        if self.is_goto():
            for entry_tree in self.entry_trees:
                if entry_tree is not None:
                    result.extend(entry_tree.get_children(recursive))
        return result

    def get_sw_components(self, recirculation=-1):
        if recirculation < 0:
            entry_trees = self.entry_trees
        else:
            entry_trees = [self.entry_trees[recirculation]]
        for entry_tree in entry_trees:
            if entry_tree is not None:
                for component in entry_tree.get_components():
                    yield component

    def get_sw_path(self, recirculation):
        if not self.entry_trees[recirculation]:
            return None
        return self.entry_trees[recirculation].get_path()

    def get_actions(self):
        result = set()
        for component in self.get_sw_components():
            result.update(component.get_actions())
        return result

    def is_bypassable(self, recirculation):
        return self.entry_trees[recirculation] is None\
                and not isinstance(self.hw_component, Conditional)

    def is_goto(self):
        return self.hw_component.is_goto()

    def validate_entry_tree(self, entry_tree, excess=False):
        logger.debug("MappedComponent: validate entry tree")
        # check that entry tree is supportable by the table
        # check for excess matches
        if entry_tree is None:
            logger.debug("null entry tree")
            return True

        excess_matches = {
            m for m in self.hw_component.get_matches()
            if m.field != 'istd.recirculation' and not m.is_optional()}
        for match in entry_tree.get_matches():
            unsupported = True
            for hwm in self.hw_component.get_matches():
                if hwm.supports(match) == Match.FULL_SUPPORT:
                    unsupported = False
                    excess_matches.discard(hwm)
                    break
            if unsupported:
                logger.debug(f"MappedComponent: {match} is unsupported")
                return False

        # check flexible mappings are supported
        base_match_kind = entry_tree.base_match_kind()
        for c in entry_tree.get_components():
            if c.flexible_match_kinds():
                continue
            if not c.base_match_kind() == base_match_kind:
                logger.debug(f"MappedComponent: conflicting match kind for {c}")
                return False

        if excess:
            logger.debug(f"MappedComponent: excess matches: {excess_matches}")
            return not excess_matches
        else:
            logger.debug(f"MappedComponent: entry tree is valid")
            return True

    def add_component(self, component, recirculation):
        logger.debug(f"MappedComponent: Add {component.name} to {self} ({recirculation})")
        if not self.hw_component.supports(component):
            logger.debug(f"MappedComponent: HW component cannot support")
            return False

        if self.entry_trees[recirculation] is None:
            new_entry_tree = EntryTree(component)
        else:
            new_entry_tree = self.entry_trees[recirculation].clone()
            # Ok build an entirely new entry tree and then merge this in and check
            # everything still works. That is much better than this trying to do
            # everything twice bs
            if not new_entry_tree.merge(EntryTree(component)):
                logger.debug(f"MappedComponent: entry tree cannot merge")
                return False

        if not self.validate_entry_tree(new_entry_tree):
            logger.debug(f"MappedComponent: invalid entry tree")
            return False

        try:
            new_entry_tree.get_path()
        except PathError:
            logger.debug(f"MappedComponent: path error in entry tree")
            return False

        self.entry_trees[recirculation] = new_entry_tree
        logger.debug(f"MappedComponent: successfully mapped {self}")
        return True

    def set_goto(self, child, recirculation):
        self.entry_trees[recirculation].set_goto(child)
        child.target.path = self.path + [
            PathElement(self.name, True, isinstance(self.hw_component, Table))]

    def __repr__(self):
        sw_components = [c.name for c in self.get_sw_components()]
        return f"{self.hw_component.name} <-- {sw_components}"

class ActionModule:
    def __init__(self, name, components_data, tables, goto_tables):
        self.name = name
        self.goto_tables = goto_tables
        self._components = []
        self._components_by_name = {}
        self.component_trees = self.resolve_components(components_data, tables)

    def get_component(self, name):
        return self._components_by_name.get(name)

    def get_components(self, name=None):
        """
        name is the name of the component from which iteration will start
        returns a generator of components
        """
        for component in self._components:
            if name is None or component.name == name:
                name = None
                yield component

    def resolve_components(self, data, tables, path=None):
        result = {}
        if data is None:
            return result
        if path is None:
            path = []
        for component_data in data:
            if component_data['type'] == 'table':
                component = tables[component_data['table']]
                if component.is_goto():
                    self.goto_tables.append(component)
            elif component_data['type'] == 'conditional':
                component = Conditional(
                    component_data['field'],
                    component_data['value'],
                    component_data.get('mask'))
            elif component_data['type'] == 'target':
                component = Target(component_data['name'], copy.copy(self.goto_tables))
            else:
                raise ValueError(f"component shouldnt be {component_data['type']}")
            component.path = path
            self._components.append(component)
            self._components_by_name[component.name] = component
            component.add_iftrue(self.resolve_components(
                component_data.get('iftrue'),
                tables,
                path + [PathElement(component.name, True, isinstance(component, Table))])
                )
            component.add_iffalse(self.resolve_components(
                component_data.get('iffalse'),
                tables,
                path + [PathElement(component.name, False, isinstance(component, Table))])
                )
            result[component.name] = component
        return result

class ComponentMap:
    def __init__(self):
        self.root_components = []
        self.map_by_mc_name = {}
        self.map_by_hwc_name = {}
        self.map_by_swc_name = {}
        self.targets = {}
        self.updated = False
        self.recirculation = 0

    def to_json_data(self):
        result = []
        for r in range(self.recirculation + 1):
            recirculation_data = {}
            for mc in self.map_by_mc_name.values():
                recirculation_data.update(mc.to_json_data(r))
            result.append(recirculation_data)
        return result

    def resolve_gotos(self):
        component_stack = copy.copy(self.root_components)
        while component_stack:
            component = component_stack.pop(0)
            goto = None
            if component_stack:
                goto = component_stack[0]
                component.resolve_gotos(goto)

    def recirculate(self):
        self.recirculation += 1
        self.updated = False
        for mc in self.map_by_mc_name.values():
            if isinstance(mc, Target):
                continue
            mc.recirculate()

    def get_mapped_component_by_hwc(self, hw_component):
        return self.map_by_hwc_name.get(hw_component.name, None)

    def can_recirculate(self):
        result = True
        components = copy.copy(self.root_components)
        while components:
            component = components.pop()
            if isinstance(component, Target):
                continue
            logger.debug(f"ComponentMap: checking {component} for recirculation")
            can_recirculate = any([
                m.field == 'istd.recirculation'
                for m in component.hw_component.get_matches()])
            if can_recirculate:
                logger.debug("ComponentMap: can recirculate")
                continue
            if component.get_actions():
                # if component does not apply actions, then it does not need
                # to distinguish packets in different recirculations
                logger.debug("ComponentMap: cannot recirculate")
                result = False
                break
            components.extend(component.get_children())
        return result

    def clone(self):
        result = ComponentMap()
        for root_component in self.root_components:
            new_component = root_component.clone()
            if isinstance(new_component, Target):
                result.add_mapped_target(new_component)
            else:
                result.add_mapped_component(new_component)
            for child in new_component.get_children(recursive=True):
                result.add_mapped_component(child)
        result.recirculation = self.recirculation
        result.updated = False
        logger.debug(f"ComponentMap: cloned {self} -- {result}")
        return result

    def find_path(self, hwc):
        logger.debug(f"ComponentMap: finding mapped path for {hwc.name}")
        logger.debug(f"ComponentMap: hw path: {hwc.path}")
        result = []
        for hwpe in hwc.path:
            # ok so I need a path element for each component that gets hit
            mc = self.map_by_hwc_name[hwpe.component]
            result.append(PathElement(mc.name, hwpe.outcome, False))
        logger.debug(f"ComponentMap: mapped path: {result}")
        return result

    def null_map(self, hwc):
        if hwc.name in self.map_by_hwc_name:
            return
        path = self.find_path(hwc)
        target = None
        if path:
            target = self.targets.get(path[0].component)
        new_component = MappedComponent(hwc, path, target)
        if path:
            parent = self.map_by_mc_name[path[-1].component]
            parent.add_child(new_component, path[-1].outcome)
        self.add_mapped_component(new_component)

    def add_mapped_component(self, mapped_component):
        self.map_by_hwc_name[mapped_component.hw_component.name] = mapped_component
        self.map_by_mc_name[mapped_component.name] = mapped_component
        for swc in mapped_component.get_sw_components():
            self.map_by_swc_name.setdefault(swc.name, []).append(mapped_component)
        if not mapped_component.path:
            self.root_components.append(mapped_component)
        self.updated = True

    def add_target(self, target):
        self.add_mapped_target(Target(target.name, copy.copy(target.goto_tables)))

    def add_mapped_target(self, target):
        self.root_components.append(target)
        self.targets[target.name] = target
        self.map_by_hwc_name[target.name] = target
        self.map_by_mc_name[target.name] = target
        logger.debug(f"ComponentMap: add mapped target: {target.name} to {self}")

    def resolve_path(self, sw_table, mapped_component):
        logger.info(f"ComponentMap: resolve path between {sw_table.name} and {mapped_component}")
        if mapped_component.path is None:
            logger.info(f"mapped component is unreachable")
            return False
        logger.debug(f"{mapped_component.entry_trees}")
        logger.debug(f"{[c.name for c in mapped_component.get_sw_components(self.recirculation)]}")
        mc_components = {c.name for c in mapped_component.get_sw_components(self.recirculation)}
        sw_path_map = {
            pe.component: pe.outcome for pe in sw_table.path
            if pe.component not in mc_components
            }
        if not sw_path_map.keys() <= self.map_by_swc_name.keys():
            if isinstance(sw_table, Table):
                logger.debug("SW Path element not mapped")
                return False
        logger.debug(sw_path_map)

        logger.debug(f"ComponentMap: path = {mapped_component.path}")
        for pe in mapped_component.path:
            pmc = self.map_by_mc_name[pe.component]
            if isinstance(pmc, Target):
                logger.debug("ComponentMap: target in path")
                continue
            et = pmc.entry_trees[self.recirculation]
            if et is None and (not pmc.is_bypassable(self.recirculation) or pe.outcome):
                logger.info(f"ComponentMap: unpassable null mapped component in path {pmc}")
                return False
            while et is not None:
                if et.component.name not in sw_path_map:
                    if isinstance(sw_table, Table):
                        logger.info(f"ComponentMap: excess component in path {et.component}")
                        return False
                elif pe.outcome != sw_path_map[et.component.name]:
                    logger.info(f"ComponentMap: {et.component} has conflicting outcomes")
                    return False
                else:
                    sw_path_map.pop(et.component.name)

                if pe.outcome:
                    if et.iffalse and not pmc.is_goto():
                        logger.info(f"ComponentMap: branching path")
                        return False
                    et = et.iftrue
                else:
                    et = et.iffalse

        remaining_path = [
            p for p in sw_table.path if p.component in sw_path_map
            ]

        if mapped_component.target is not None:
            if remaining_path:
                logger.info(f"ComponentMap: remaining_path: {remaining_path}")
                last_pe = remaining_path.pop()
                if last_pe.component not in self.map_by_swc_name:
                    logger.debug("ComponentMap: SW Path element not mapped")
                    return False
                potential_parents = {
                    p for p in self.map_by_swc_name[last_pe.component]
                    if p.hw_component in mapped_component.target.goto_tables
                    }
                if not potential_parents:
                    logger.debug("ComponentMap: no potential parents")
                    return False
                remaining_path = []

        if isinstance(sw_table, Table) and remaining_path:
            logger.info(f"ComponentMap: missing path elements: {remaining_path}")
            return False

        return True


    def map(self, hw_table, sw_table):
        logger.info(f"ComponentMap: map {sw_table.name} to {hw_table.name}")
        result = False
        if isinstance(sw_table, Table) and sw_table.name in self.map_by_swc_name:
            logger.debug(f"ComponentMap: {sw_table.name} already mapped")
            return result
        if hw_table.name in self.map_by_hwc_name:
            mapped_component = self.map_by_hwc_name[hw_table.name]
        else:
            # create new Mapped Component for hw table
            mc_path = self.find_path(hw_table)
            if mc_path is None:
                logger.info(f"unreachable hw table")
                return False

            target = None
            if mc_path:
                # target is always first component in hw path, if not in
                # self.targets then its not a target
                target = self.targets.get(mc_path[0].component)

            mapped_component = MappedComponent(hw_table, mc_path, target)
            if mc_path:
                self.map_by_mc_name[mc_path[-1].component].add_child(
                    mapped_component, mc_path[-1].outcome)
        logger.info(f"ComponentMap: mapped component: {mapped_component}")

        if sw_table in mapped_component.get_sw_components():
            logger.info("sw component already mapped to hw component")
            return False

        # validate path dont worry about paths for conditionals, they will
        # be pruned later and dont worry about paths for goto tables, they
        # will be fixed later
        if not self.resolve_path(sw_table, mapped_component):
            logger.info("ComponentMap: path resolution failed")
            return False

        result = mapped_component.add_component(sw_table, self.recirculation)
        if result:
            self.add_mapped_component(mapped_component)
        else:
            logger.info("could not add component")
        return result

    def get_mapping_pairs(self):
        result = set()
        for swcn, hwcs in self.map_by_swc_name.items():
            result.update({(swcn, hwc.hw_component.name) for hwc in hwcs})
        return result

    def outclasses(self, other, check_paths=False):
        if len(other.map_by_swc_name) > len(self.map_by_swc_name):
            # if the other maps more software components than this then it
            # cannot be outclassed
            return False
        if check_paths:
            return self.get_mapping_pairs() >= other.get_mapping_pairs()
        else:
            return self.map_by_swc_name.keys() > other.map_by_swc_name.keys()

    def __repr__(self):
        return repr([v for v in self.map_by_hwc_name.values()])

class ModuleMap:
    def __init__(self, hw_module, sw_module, cmaps):
        self.hw_module = hw_module
        self.sw_module = sw_module
        self._potential_maps = {}
        self._mergeable_tables = {}
        self.find_potential_table_mappings()
        self.find_mergeable_tables()
        if cmaps is None:
            self.cmaps = [ComponentMap()]
        else:
            self.cmaps = cmaps

    def find_potential_table_mappings(self):
        # for every action table, find all of the potential ways it can be mapped
        for sw_component in self.sw_module.get_components():
            logger.debug(f"ModuleMap: find potential mappings for {sw_component.name}")
            supported = False
            for hw_component in self.hw_module.get_components():
                logger.debug(f"ModuleMap: check {hw_component.name}")
                if hw_component.supports(sw_component):
                    supported = True
                    logger.info(f"ModuleMap: {hw_component.name} supports {sw_component.name}")
                    self._potential_maps.setdefault(
                        hw_component.name, set()).add(sw_component.name)
            if not supported:
                logger.info(f"ModuleMap: {sw_component.name} is unsupported")

    def find_mergeable_tables(self):
        # software tables may or may not be mergeable with other tables
        # depending on how they are defined. We can find mergeable combinations
        # without worrying about the hardware
        for c1 in self.sw_module.get_components():
            for c2 in self.sw_module.get_components(name=c1.name):
                if c1 == c2:
                    continue
                if c1.can_merge(c2):
                    self._mergeable_tables.setdefault(c1.name, set()).add(c2.name)
                    self._mergeable_tables.setdefault(c2.name, set()).add(c1.name)

    def map(self):
        logger.info(f"ModuleMap: find mappings from {self.sw_module.name} to {self.hw_module.name}")
        for hwc in self.hw_module.get_components():
            logger.info(f"ModuleMap: ----- find mappings for {hwc.name} -----")
            if isinstance(hwc, Target):
                for cmap in self.cmaps:
                    cmap.add_target(hwc)
                continue
            if hwc.name not in self._potential_maps:
                logger.info(f"ModuleMap: no potential maps")
                for cmap in self.cmaps:
                    cmap.null_map(hwc)
                continue
            potentials = [
                s for s in self.sw_module.get_components()\
                if s.name in self._potential_maps[hwc.name]
                ]
            for swc in potentials:
                logger.info(f"ModuleMap: potential - {swc.name}")
                new_cmaps = []
                for cmap in self.cmaps:
                    logger.info(f"ModuleMap: cmap - {cmap}")
                    # for each cmap for each swc we add two cmaps, one where we
                    # map and one where we do not
                    new_cmaps.append(cmap)
                    new_cmap = cmap.clone()
                    # TODO: it is possible this mergeable tables check is a
                    # waste of time. Check that later on
                    #mapped_component = cmap.get_mapped_component_by_hwc(hwc)
                    #if mapped_component is not None:
                    #    for mswc in mapped_component.get_sw_components(cmap.recirculation):
                    #        if swc.name not in self._mergeable_tables.get(mswc.name, []):
                    #            logging.debug(f"ModuleMap: {swc.name} cannot be merged with {mswc.name}")
                    #            continue
                    if new_cmap.map(hwc, swc):
                        new_cmaps.append(new_cmap)
                self.cmaps = new_cmaps
            for cmap in self.cmaps:
                if hwc.name not in cmap.map_by_hwc_name:
                    cmap.null_map(hwc)
            valid_cmaps = []
            for cmap in self.cmaps:
                mc = cmap.map_by_hwc_name[hwc.name]
                if mc.validate_entry_tree(mc.entry_trees[cmap.recirculation], excess=True):
                    valid_cmaps.append(cmap)
            self.cmaps = valid_cmaps
        new_cmaps = []
        swc_names = [c.name for c in self.sw_module.get_components()]
        self.prune_outclassed_cmaps(check_paths=True)

    def get_complete_cmaps(self):
        result = []
        for cmap in self.cmaps:
            logger.info(f"ModuleMap: check {cmap} for completeness")
            swc_names = [c.name for c in self.sw_module.get_components()]
            if all([n in cmap.map_by_swc_name for n in swc_names]):
                result.append(cmap)
                logger.info(f"ModuleMap: {cmap} is complete")
            else:
                logger.info(f"ModuleMap: {cmap} is not complete")
                missing_swc_names = [n for n in swc_names if n not in cmap.map_by_swc_name]
                logger.info(f"ModuleMap: missing components = {missing_swc_names}")
        return result

    def prune_outclassed_cmaps(self, check_paths=False):
        # TODO: ok there is an interesting bug here. So when you have a big
        # tree of conditionals, so an iffalse then an iftrue then a table, it
        # seems to want the iffalse to be included in the table with the table
        # so if the table has exact matches, then it wont get merged in.
        # so there should be two reasons this shouldnt happen, you should be
        # just able to have the conditionals in one table and then the table
        # in the next, and I dont know why it doesnt find that solution.
        logger.info(f"prune outclassed cmaps, initial count: {len(self.cmaps)}")
        new_cmaps = []
        self.cmaps = sorted(self.cmaps, key=lambda x: len(x.map_by_swc_name))
        while self.cmaps:
            cmap = self.cmaps.pop(0)
            outclassed = False
            for other in self.cmaps:
                if other.outclasses(cmap, check_paths):
                    outclassed = True
                    break
            if not outclassed:
                new_cmaps.append(cmap)
        self.cmaps = new_cmaps
        if len(self.cmaps) > 100:
            self.cmaps = new_cmaps[-100:]
        logger.info(f"remaining cmaps: {len(self.cmaps)}")
        for c in self.cmaps:
            logger.info(f"{c}")

    def get_potential_map(self, name):
        return self._potential_maps.get(name, [])

    def get_mergeable_tables(self, name):
        return self._mergeable_tables.get(name, set())

class Pipeline:
    def __init__(self, name, data):
        self.name = name
        self.cmaps = [ComponentMap()]
        self.pipeline = data['pipeline']
        self.actions = {}
        self.tables = {}
        self.action_modules = []
        for name, action_data in data['actions'].items():
            self.actions[name] = Action(name, action_data)
        for name, table_data in data['tables'].items():
            self.tables[name] = Table(name, table_data, self.actions)
        goto_tables = []
        for action_module_data in self.pipeline:
            for name, components_data in action_module_data.items():
                am = ActionModule(name, components_data, self.tables, goto_tables)
                self.action_modules.append(am)
                goto_tables = copy.copy(am.goto_tables)

    def map(self, other):
        # self is hardware, other is software
        hw_pipeline = self
        sw_pipeline = other
        hw_modules = copy.copy(hw_pipeline.action_modules)
        recirculations = 0
        # so we iterate over the sw_pipeline looking for potential solutions
        for sw_module in sw_pipeline.action_modules:
            logger.info("ModuleMap: =================")
            logger.info(f"Pipeline: Find mappings for module {sw_module.name}")
            logger.info("ModuleMap: =================")
            complete_cmaps = []
            while self.cmaps and not complete_cmaps and recirculations < 8:
                while hw_modules and not complete_cmaps:
                    hw_module = hw_modules.pop(0)
                    logger.info("ModuleMap: -----------------")
                    logger.info(f"Pipeline: Find mappings to {hw_module.name}")
                    logger.info("ModuleMap: -----------------")
                    module_map = ModuleMap(hw_module, sw_module, self.cmaps)
                    module_map.map()
                    module_map.prune_outclassed_cmaps()
                    complete_cmaps = module_map.get_complete_cmaps()
                    if not complete_cmaps:
                        self.cmaps = copy.copy(module_map.cmaps)
                if not complete_cmaps:
                    # recirculate
                    hw_modules = copy.copy(hw_pipeline.action_modules)
                    recirculations += 1
                    # check for any progress, if no cmap has been updated no
                    # point trying another recirculation
                    new_cmaps = []
                    for cmap in self.cmaps:
                        if cmap.updated and cmap.can_recirculate():
                            cmap.recirculate()
                            new_cmaps.append(cmap)
                    if new_cmaps:
                        logger.info(f"Pipeline: ===================")
                        logger.info(f"Pipeline: New recirculation: {recirculations}")
                    self.cmaps = new_cmaps
            if not complete_cmaps:
                break
            self.cmaps = complete_cmaps

        return complete_cmaps
