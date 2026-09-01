import os
from parser.hcl_parser import parse_file, build_graph

def count_corpus_resources(corpus_dir):
    total_files = 0
    total_resources = 0
    sg_resources = 0
    iam_resources = 0
    parse_errors = 0
    
    for root, _, files in os.walk(corpus_dir):
        for f in files:
            if f.endswith(".tf"):
                total_files += 1
                full_path = os.path.join(root, f)
                try:
                    parsed = parse_file(full_path)
                    graph = build_graph(parsed)
                    total_resources += len(graph.resources)
                    for r in graph.resources.values():
                        if r.type in ("aws_security_group", "aws_security_group_rule"):
                            sg_resources += 1
                        elif r.type in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_role"):
                            iam_resources += 1
                except Exception:
                    parse_errors += 1
                    
    return {
        "files": total_files,
        "total_resources": total_resources,
        "sg_resources": sg_resources,
        "iam_resources": iam_resources,
        "parse_errors": parse_errors
    }

terragoat_stats = count_corpus_resources("fixtures/corpora/terragoat")
sadcloud_stats = count_corpus_resources("fixtures/corpora/sadcloud")

print("TERRAGOAT STATS:", terragoat_stats)
print("SADCLOUD STATS:", sadcloud_stats)
