from family_tree.models import ParentalRelationship, Partnership, FamilyMember

from collections import deque
from collections import defaultdict, deque
from django.db.models import Q

# def get_full_hierarchy_from_member(start_member, family_tree, view_type="all"):
#     """
#     Optimized hierarchy traversal
#     DB Queries: 2 (constant)
#     """

#     # ==========================
#     # PREFETCH DATA (2 QUERIES)
#     # ==========================
#     parental_rels = list(
#         ParentalRelationship.objects.filter(
#             family_tree=family_tree,
#             is_deleted=False
#         ).select_related("father", "mother", "child")
#     )

#     partnerships = list(
#         Partnership.objects.filter(
#             family_tree=family_tree,
#             is_deleted=False
#         ).select_related("husband", "wife")
#     )

#     # ==========================
#     # BUILD LOOKUP MAPS
#     # ==========================
#     parents_by_child = {}
#     children_by_parents = defaultdict(list)
#     spouse_map = {}

#     # Parents / children
#     for rel in parental_rels:
#         parents_by_child[rel.child_id] = rel

#         key = (rel.father_id, rel.mother_id)
#         children_by_parents[key].append(rel.child)

#     # Spouse map
#     for p in partnerships:
#         if p.husband_id and p.wife_id:
#             spouse_map[p.husband_id] = p.wife
#             spouse_map[p.wife_id] = p.husband

#     # ==========================
#     # BFS TRAVERSAL
#     # ==========================
#     visited = set()
#     queue = deque([start_member])
#     result = []

#     while queue:
#         member = queue.popleft()

#         if not member or member.id in visited:
#             continue

#         visited.add(member.id)
#         result.append(member)

#         # =====================
#         # PARENTS
#         # =====================
#         parent_rel = parents_by_child.get(member.id)

#         if parent_rel:
#             if view_type in ("all", "paternal") and parent_rel.father:
#                 queue.append(parent_rel.father)

#             if view_type in ("all", "maternal") and parent_rel.mother:
#                 queue.append(parent_rel.mother)

#         # =====================
#         # SPOUSE
#         # =====================
#         spouse = spouse_map.get(member.id)
#         if spouse:
#             queue.append(spouse)

#         # =====================
#         # CHILDREN (VIA PARTNERSHIP)
#         # =====================
#         if spouse:
#             if view_type == "paternal" and member.gender == "male":
#                 children = children_by_parents.get((member.id, spouse.id), [])

#             elif view_type == "maternal" and member.gender == "female":
#                 children = children_by_parents.get((spouse.id, member.id), [])

#             else:  # all
#                 children = (
#                     children_by_parents.get((member.id, spouse.id), []) +
#                     children_by_parents.get((spouse.id, member.id), [])
#                 )

#             for child in children:
#                 queue.append(child)

#         # =====================
#         # SIBLINGS
#         # =====================
#         if parent_rel:
#             sibling_keys = []

#             if view_type in ("all", "paternal") and parent_rel.father:
#                 sibling_keys.append((parent_rel.father_id, parent_rel.mother_id))

#             if view_type in ("all", "maternal") and parent_rel.mother:
#                 sibling_keys.append((parent_rel.father_id, parent_rel.mother_id))

#             for key in sibling_keys:
#                 for sib in children_by_parents.get(key, []):
#                     if sib.id != member.id:
#                         queue.append(sib)

#     return result



def get_full_hierarchy_from_member(start_member, family_tree, stop_at_member_id=None):
    """
    Optimized hierarchy traversal using cached parent fields + partnerships
    Total DB Queries: 2
    
    Args:
        start_member: FamilyMember to start traversal from
        family_tree: FamilyTree instance
        stop_at_member_id: Optional - include this member but don't traverse their ancestors
    
    Returns:
        List of FamilyMember objects in the hierarchy
    """
    
    # ==========================
    # PREFETCH ALL DATA (2 QUERIES)
    # ==========================
    members = list(
        FamilyMember.objects.filter(
            family_tree=family_tree,
            is_deleted=False
        ).select_related("primary_father", "primary_mother")
    )
    
    partnerships = list(
        Partnership.objects.filter(
            family_tree=family_tree,
            is_deleted=False
        ).select_related("husband", "wife")
    )
    
    # ==========================
    # BUILD IN-MEMORY LOOKUP MAPS
    # ==========================
    member_by_id = {m.id: m for m in members}
    spouse_map = {}  # member_id -> spouse
    children_by_parent = defaultdict(list)  # parent_id -> [children]
    siblings_map = defaultdict(set)  # member_id -> {sibling_ids}
    
    # Build spouse lookup
    for p in partnerships:
        if p.husband_id and p.wife_id:
            spouse_map[p.husband_id] = p.wife
            spouse_map[p.wife_id] = p.husband
    
    # Build children lookup and siblings map
    parent_groups = defaultdict(list)  # (father_id, mother_id) -> [children]
    
    for m in members:
        # Map each parent to their children
        if m.primary_father_id:
            children_by_parent[m.primary_father_id].append(m)
        if m.primary_mother_id:
            children_by_parent[m.primary_mother_id].append(m)
        
        # Group children by parent pair for sibling relationships
        if m.primary_father_id or m.primary_mother_id:
            key = (m.primary_father_id, m.primary_mother_id)
            parent_groups[key].append(m)
    
    # Build sibling relationships
    for siblings_list in parent_groups.values():
        if len(siblings_list) > 1:
            for member in siblings_list:
                siblings_map[member.id] = {s.id for s in siblings_list if s.id != member.id}
    
    # ==========================
    # BFS TRAVERSAL
    # ==========================
    visited = set()
    queue = deque([start_member])
    result = []
    
    while queue:
        member = queue.popleft()
        
        if not member or member.id in visited:
            continue
        
        visited.add(member.id)
        result.append(member)
        
        # Check if we should stop traversing ancestors from this member
        should_skip_ancestors = (stop_at_member_id and member.id == stop_at_member_id)
        
        # =====================
        # PARENTS (Skip if this is the stop member)
        # =====================
        if not should_skip_ancestors:
            if member.primary_father and member.primary_father.id not in visited:
                queue.append(member.primary_father)
            
            if member.primary_mother and member.primary_mother.id not in visited:
                queue.append(member.primary_mother)
            
            # =====================
            # SIBLINGS (Skip if this is the stop member)
            # =====================
            sibling_ids = siblings_map.get(member.id, set())
            for sibling_id in sibling_ids:
                if sibling_id not in visited:
                    sibling = member_by_id.get(sibling_id)
                    if sibling:
                        queue.append(sibling)
        
        # =====================
        # CHILDREN (Always include)
        # =====================
        children = children_by_parent.get(member.id, [])
        for child in children:
            if child.id not in visited:
                queue.append(child)
        
        # =====================
        # SPOUSE (Always include)
        # =====================
        spouse = spouse_map.get(member.id)
        if spouse and spouse.id not in visited:
            queue.append(spouse)
    
    return result

