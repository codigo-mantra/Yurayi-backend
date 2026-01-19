from family_tree.models import ParentalRelationship

def get_parents(member):
    rel = ParentalRelationship.objects.filter(
        child=member,
        is_deleted=False
    ).first()

    if not rel:
        return None, None

    return rel.father, rel.mother


def traverse_ancestors(member, mode, visited):
    if member.id in visited:
        return

    visited.add(member.id)

    father, mother = get_parents(member)

    if mode in ("all", "paternal") and father:
        traverse_ancestors(father, mode, visited)

    if mode in ("all", "maternal") and mother:
        traverse_ancestors(mother, mode, visited)


def traverse_descendants(member, visited):
    relations = ParentalRelationship.objects.filter(
        father=member,
        is_deleted=False
    ) | ParentalRelationship.objects.filter(
        mother=member,
        is_deleted=False
    )

    for rel in relations:
        child = rel.child
        if child.id not in visited:
            visited.add(child.id)
            traverse_descendants(child, visited)


def get_filtered_tree(root_member, view_type):
    visited = set()

    # Always include root
    visited.add(root_member.id)

    # Ancestors
    traverse_ancestors(root_member, view_type, visited)

    # Descendants
    traverse_descendants(root_member, visited)

    return visited
