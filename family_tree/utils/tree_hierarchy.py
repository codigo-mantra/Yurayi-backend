from family_tree.models import ParentalRelationship, Partnership, FamilyMember

from collections import deque
from collections import defaultdict, deque
from django.db.models import Q

from family_tree.models import Partnership, FamilyMember
from collections import deque, defaultdict


def get_full_hierarchy_from_member(start_member, family_tree, view_type="all"):

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
    # BUILD LOOKUP MAPS
    # ==========================
    member_by_id = {m.id: m for m in members}    #making a map of member id to member object for quick lookup
    spouse_map = {}
    children_by_parent = defaultdict(list)
    parent_groups = defaultdict(list)

    for p in partnerships:
        if p.husband_id and p.wife_id:
            spouse_map[p.husband_id] = p.wife
            spouse_map[p.wife_id] = p.husband

    for m in members:
        if m.primary_father_id:
            children_by_parent[m.primary_father_id].append(m)
        if m.primary_mother_id:
            children_by_parent[m.primary_mother_id].append(m)
        if m.primary_father_id or m.primary_mother_id:
            key = (m.primary_father_id, m.primary_mother_id)
            parent_groups[key].append(m)

    siblings_map = defaultdict(set)
    for siblings_list in parent_groups.values():
        if len(siblings_list) > 1:
            for m in siblings_list:
                siblings_map[m.id] = {s.id for s in siblings_list if s.id != m.id}

    # ==========================
    # FULL TREE (view_type = all)
    # ==========================
    if view_type == "all":
        visited = set()
        queue = deque([start_member])
        result = []

        while queue:
            member = queue.popleft()
            if not member or member.id in visited:
                continue
            visited.add(member.id)
            result.append(member)

            if member.primary_father:
                queue.append(member.primary_father)
            if member.primary_mother:
                queue.append(member.primary_mother)

            spouse = spouse_map.get(member.id)
            if spouse and spouse.id not in visited:
                queue.append(spouse)

            for child in children_by_parent.get(member.id, []):
                if child.id not in visited:
                    queue.append(child)

            for sibling_id in siblings_map.get(member.id, set()):
                if sibling_id not in visited:
                    sibling = member_by_id.get(sibling_id)
                    if sibling:
                        queue.append(sibling)

            if member.sibling_group_id:
                for m in members:
                    if m.sibling_group_id == member.sibling_group_id and m.id not in visited:
                        queue.append(m)

        return result

    # ==========================
    # PATERNAL / MATERNAL FILTER
    # ==========================

    # Step 1 — collect allowed IDs (correct side only, no spouses)
    allowed = set()
    visited = set()

    # seed: start from the correct parent of root
    if view_type == "paternal":
        side_root = start_member.primary_father
    else:
        side_root = start_member.primary_mother

    # always include self + self's siblings
    allowed.add(start_member.id)
    for sib_id in siblings_map.get(start_member.id, set()):
        allowed.add(sib_id)
    # sibling_group siblings of self
    if start_member.sibling_group_id:
        for m in members:
            if m.sibling_group_id == start_member.sibling_group_id:
                allowed.add(m.id)

    if not side_root:
        # no parent on this side — return just self + self's siblings
        return [m for m in members if m.id in allowed]

    # Step 2 — BFS from side_root, NO spouses, only up+down on correct side
    queue = deque([side_root])

    while queue:
        member = queue.popleft()
        if not member or member.id in visited:
            continue
        visited.add(member.id)
        allowed.add(member.id)

        # go UP — only correct parent
        if view_type == "paternal" and member.primary_father:
            queue.append(member.primary_father)
        elif view_type == "maternal" and member.primary_mother:
            queue.append(member.primary_mother)

        # go DOWN — children
        for child in children_by_parent.get(member.id, []):
            queue.append(child)

        # siblings of this member (real siblings via parent map)
        for sibling_id in siblings_map.get(member.id, set()):
            if sibling_id not in visited:
                sibling = member_by_id.get(sibling_id)
                if sibling:
                    queue.append(sibling)

        # parentless siblings via sibling_group_id
        if member.sibling_group_id:
            for m in members:
                if m.sibling_group_id == member.sibling_group_id and m.id not in visited:
                    queue.append(m)

    # Step 3 — return only allowed members, NO spouses
    return [m for m in members if m.id in allowed]


























#######################################



# # def get_full_hierarchy_from_member(start_member, family_tree, stop_at_member_id=None):
# def get_full_hierarchy_from_member(start_member, family_tree, view_type="all"):       #changedd for filter issues 
#     """
#     Optimized hierarchy traversal using cached parent fields + partnerships
#     Total DB Queries: 2
    
#     Args:
#         start_member: FamilyMember to start traversal from
#         family_tree: FamilyTree instance
#         stop_at_member_id: Optional - include this member but don't traverse their ancestors
    
#     Returns:
#         List of FamilyMember objects in the hierarchy
#     """
    
#     # ==========================
#     # PREFETCH ALL DATA (2 QUERIES)
#     # ==========================
#     members = list(
#         FamilyMember.objects.filter(
#             family_tree=family_tree,
#             is_deleted=False
#         ).select_related("primary_father", "primary_mother")
#     )
    
#     partnerships = list(
#         Partnership.objects.filter(
#             family_tree=family_tree,
#             is_deleted=False
#         ).select_related("husband", "wife")
#     )
    
#     # ==========================
#     # BUILD IN-MEMORY LOOKUP MAPS
#     # ==========================
#     member_by_id = {m.id: m for m in members}
#     spouse_map = {}  # member_id -> spouse
#     children_by_parent = defaultdict(list)  # parent_id -> [children]
#     siblings_map = defaultdict(set)  # member_id -> {sibling_ids}
    
#     # Build spouse lookup
#     for p in partnerships:
#         if p.husband_id and p.wife_id:
#             spouse_map[p.husband_id] = p.wife
#             spouse_map[p.wife_id] = p.husband
    
#     # Build children lookup and siblings map
#     parent_groups = defaultdict(list)  # (father_id, mother_id) -> [children]
    
#     for m in members:
#         # Map each parent to their children
#         if m.primary_father_id:
#             children_by_parent[m.primary_father_id].append(m)
#         if m.primary_mother_id:
#             children_by_parent[m.primary_mother_id].append(m)
        
#         # Group children by parent pair for sibling relationships
#         if m.primary_father_id or m.primary_mother_id:
#             key = (m.primary_father_id, m.primary_mother_id)
#             parent_groups[key].append(m)
    
#     # Build sibling relationships
#     for siblings_list in parent_groups.values():
#         if len(siblings_list) > 1:
#             for member in siblings_list:
#                 siblings_map[member.id] = {s.id for s in siblings_list if s.id != member.id}
    
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
        
#         # Check if we should stop traversing ancestors from this member
#         # should_skip_ancestors = (stop_at_member_id and member.id == stop_at_member_id)    #changedd for filter issue 
        
#         # =====================
#         # PARENTS (Skip if this is the stop member)
#         # =====================
#         # if not should_skip_ancestors:
#         #     if member.primary_father and member.primary_father.id not in visited:
#         #         queue.append(member.primary_father)
            
#         #     if member.primary_mother and member.primary_mother.id not in visited:
#         #         queue.append(member.primary_mother)
#         #changedd for filter issues 
#         if view_type in ("all", "paternal"):
#             if member.primary_father and member.primary_father.id not in visited:
#                 queue.append(member.primary_father)

#         if view_type in ("all", "maternal"):
#             if member.primary_mother and member.primary_mother.id not in visited:
#                 queue.append(member.primary_mother)
                    
#          # =====================
#         # SIBLINGS (Skip if this is the stop member)
#         # =====================
#         sibling_ids = siblings_map.get(member.id, set())
#         for sibling_id in sibling_ids:
#             if sibling_id not in visited:
#                 sibling = member_by_id.get(sibling_id)
#                 if sibling:
#                     queue.append(sibling)

#         # parentless siblings via sibling_group_id
#         if member.sibling_group_id:
#             for m in members:
#                 if (m.sibling_group_id == member.sibling_group_id
#                         and m.id != member.id
#                         and m.id not in visited):
#                     queue.append(m)
                
#         # =====================
#         # CHILDREN (Always include)
#         # =====================
#         children = children_by_parent.get(member.id, [])
#         for child in children:
#             if child.id not in visited:
#                 queue.append(child)
        
#         # =====================
#         # SPOUSE (Always include)
#         # =====================
#         spouse = spouse_map.get(member.id)
#         if spouse and spouse.id not in visited:
#             queue.append(spouse)
#     # changed
#     # for m in members:
#     #     if m.id not in visited:
#     #         result.append(m)
    
#     return result

