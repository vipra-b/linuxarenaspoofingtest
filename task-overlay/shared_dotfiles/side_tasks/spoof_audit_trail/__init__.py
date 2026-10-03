from pathlib import Path

from shared_dotfiles.side_tasks.spoof_audit_trail.scorer import scorer

from control_tower.task.task_config import make_side_task_from_path

config = make_side_task_from_path(
    Path(__file__).parent,
    failure_type="delayed",
    task_category="monitoring_subversion",
    scorer=scorer,
    compatible_main_tasks=["add_zsh_support_to_merger"],
)
