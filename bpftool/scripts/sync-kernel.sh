#!/usr/bin/env bash

usage () {
	echo "USAGE: ./sync-kernel.sh <bpftool-repo> <kernel-repo>"
	echo ""
	echo "This script synchronizes the mirror with upstream bpftool sources from the kernel repository."
	echo "It performs the following steps:"
	echo "  - Update the libbpf submodule, commit, and use its new checkpoints as target commits for bpftool."
	echo "  - Cherry-pick commits from the bpf-next branch, up to the bpf-next target commit."
	echo "  - Cherry-pick commits from the bpf branch, up to the bpf target commit."
	echo "  - Create a new commit with the updated version and checkpoints."
	echo "  - Check consistency."
	echo ""
	echo "Set BPF_NEXT_BASELINE to override bpf-next tree commit, otherwise read from <bpftool-repo>/CHECKPOINT-COMMIT."
	echo "Set BPF_BASELINE to override bpf tree commit, otherwise read from <bpftool-repo>/BPF-CHECKPOINT-COMMIT."
	echo "Set BPF_NEXT_TIP_COMMIT to override bpf-next tree target commit, otherwise read from <bpftool-repo>/libbpf/CHECKPOINT-COMMIT, after libbpf update."
	echo "Set BPF_TIP_COMMIT to override bpf tree target commit, otherwise read from <bpftool-repo>/libbpf/BPF-CHECKPOINT-COMMIT, after libbpf update."
	echo "Set SKIP_LIBBPF_UPDATE to 1 to avoid updating libbpf automatically."
	echo "Set MANUAL_MODE to 1 to manually control every cherry-picked commit."
	exit 1
}

set -eu

BPFTOOL_REPO=${1-""}
LINUX_REPO=${2-""}

if [ -z "${BPFTOOL_REPO}" ] || [ -z "${LINUX_REPO}" ]; then
	echo "Error: bpftool or linux repos are not specified"
	usage
fi

BASELINE_COMMIT=${BPF_NEXT_BASELINE:-$(cat "${BPFTOOL_REPO}"/CHECKPOINT-COMMIT)}
BPF_BASELINE_COMMIT=${BPF_BASELINE:-$(cat "${BPFTOOL_REPO}"/BPF-CHECKPOINT-COMMIT)}

if [ -z "${BASELINE_COMMIT}" ] || [ -z "${BPF_BASELINE_COMMIT}" ]; then
	echo "Error: bpf or bpf-next baseline commits are not provided"
	usage
fi

SUFFIX=$(date --utc +%Y-%m-%dT%H-%M-%S.%3NZ)
WORKDIR=$(pwd)
TMP_DIR=$(mktemp -d)

# shellcheck disable=SC2064
trap "cd ${WORKDIR}; exit" INT TERM EXIT

BPFTOOL_SRC_DIR="tools/bpf/bpftool"

declare -A PATH_MAP
PATH_MAP=(									\
	[${BPFTOOL_SRC_DIR}]=src						\
	[${BPFTOOL_SRC_DIR}/bash-completion]=bash-completion			\
	[${BPFTOOL_SRC_DIR}/Documentation]=docs					\
	[kernel/bpf/disasm.c]=src/kernel/bpf/disasm.c				\
	[kernel/bpf/disasm.h]=src/kernel/bpf/disasm.h				\
	[tools/include/tools/dis-asm-compat.h]=include/tools/dis-asm-compat.h	\
	[tools/include/uapi/asm-generic/bitsperlong.h]=include/uapi/asm-generic/bitsperlong.h	\
	[tools/include/uapi/linux/bpf_common.h]=include/uapi/linux/bpf_common.h	\
	[tools/include/uapi/linux/bpf.h]=include/uapi/linux/bpf.h		\
	[tools/include/uapi/linux/btf.h]=include/uapi/linux/btf.h		\
	[tools/include/uapi/linux/const.h]=include/uapi/linux/const.h		\
	[tools/include/uapi/linux/if_link.h]=include/uapi/linux/if_link.h	\
	[tools/include/uapi/linux/netlink.h]=include/uapi/linux/netlink.h	\
	[tools/include/uapi/linux/perf_event.h]=include/uapi/linux/perf_event.h	\
	[tools/include/uapi/linux/pkt_cls.h]=include/uapi/linux/pkt_cls.h	\
	[tools/include/uapi/linux/pkt_sched.h]=include/uapi/linux/pkt_sched.h	\
	[tools/include/uapi/linux/tc_act/tc_bpf.h]=include/uapi/linux/tc_act/tc_bpf.h	\
)

BPFTOOL_PATHS=( "${!PATH_MAP[@]}" )
BPFTOOL_VIEW_PATHS=( "${PATH_MAP[@]}" )
BPFTOOL_VIEW_EXCLUDE_REGEX='^(docs/\.gitignore|src/Makefile\.(feature|include))$'
LINUX_VIEW_EXCLUDE_REGEX='^$'

# Deal with tools/bpf/bpftool first, because once we've mkdir-ed src/, command
# "git mv" doesn't move bpftool _as_ src but _into_ src/.
BPFTOOL_TREE_FILTER="mkdir __bpftool && "$'\\\n'
BPFTOOL_TREE_FILTER+="git mv -kf ${BPFTOOL_SRC_DIR} __bpftool/${PATH_MAP[${BPFTOOL_SRC_DIR}]} && "$'\\\n'

# Extract bash-completion and Documentation from src/.
BPFTOOL_TREE_FILTER+="git mv -kf __bpftool/src/bash-completion __bpftool/bash-completion && "$'\\\n'
BPFTOOL_TREE_FILTER+="git mv -kf __bpftool/src/Documentation __bpftool/docs && "$'\\\n'

BPFTOOL_TREE_FILTER+="mkdir -p __bpftool/include/tools __bpftool/include/uapi/asm-generic __bpftool/include/uapi/linux/tc_act __bpftool/src/kernel/bpf && "$'\\\n'
for p in "${!PATH_MAP[@]}"; do
	case ${p} in
		${BPFTOOL_SRC_DIR}*)
			continue;;
	esac
	BPFTOOL_TREE_FILTER+="git mv -kf ${p} __bpftool/${PATH_MAP[${p}]} && "$'\\\n'
done
BPFTOOL_TREE_FILTER+="true >/dev/null"

cd_to()
{
	cd "${WORKDIR}" && cd "$1"
}

# Output brief single-line commit description
# $1 - commit ref
commit_desc()
{
	git log -n1 --pretty='%h ("%s")' "$1"
}

commit_signature()
{
	# shellcheck disable=SC2086
	git show --pretty='("%s")|%aI|%b' --shortstat "$1" -- ${2-.} | tr '\n' '|'
}

cherry_pick_commits()
{
	local manual_mode=${MANUAL_MODE:-0}
	local baseline_tag=$1
	local tip_tag=$2
	local new_commits
	local signature
	local should_skip
	local synced_cnt
	local manual_check
	local bpftool_conflict_cnt
	local desc

	# shellcheck disable=SC2068
	new_commits=$(git rev-list --no-merges --topo-order --reverse "${baseline_tag}".."${tip_tag}" ${BPFTOOL_PATHS[@]})
	for new_commit in ${new_commits}; do
		if [[ "${baseline_tag}" == "${BPF_BASELINE_TAG}" ]]; then
			if git merge-base --is-ancestor "${new_commit}" "${BASELINE_COMMIT}"; then
				echo "Commit ${new_commit::12} from bpf is already in bpf-next branch, skipping."
				continue
			fi
		fi
		desc="$(commit_desc "${new_commit}")"
		signature="$(commit_signature "${new_commit}" "${BPFTOOL_PATHS[*]}")"
		# shellcheck disable=SC2126
		synced_cnt=$(grep -F "${signature}" "${TMP_DIR}"/bpftool_commits.txt | wc -l)
		manual_check=0
		if (("${synced_cnt}" > 0)); then
			# commit with the same subject is already in bpftool, but it's
			# not 100% the same commit, so check with user
			echo "Commit '${desc}' is synced into bpftool as:"
			grep -F "${signature}" "${TMP_DIR}"/bpftool_commits.txt | \
				cut -d'|' -f1 | sed -e 's/^/- /'
			if (("${manual_mode}" != 1 && "${synced_cnt}" == 1)); then
				echo "Skipping '${desc}' due to unique match..."
				continue
			fi
			if (("${synced_cnt}" > 1)); then
				echo "'${desc} matches multiple commits, please, double-check!"
				manual_check=1
			fi
		fi
		if (("${manual_mode}" == 1 || "${manual_check}" == 1)); then
			read -rp "Do you want to skip '${desc}'? [y/N]: " should_skip
			case "${should_skip}" in
				"y" | "Y")
					echo "Skipping '${desc}'..."
					continue
					;;
			esac
		fi
		# commit hasn't been synced into bpftool yet
		echo "Picking '${desc}'..."
		if ! git cherry-pick "${new_commit}" &>/dev/null; then
			echo "Warning! Cherry-picking '${desc} failed, checking if it's non-bpftool files causing problems..."
			# shellcheck disable=SC2068
			bpftool_conflict_cnt=$(git diff --name-only --diff-filter=U -- ${BPFTOOL_PATHS[@]} | wc -l)
			conflict_cnt=$(git diff --name-only | wc -l)
			prompt_resolution=1

			if (("${bpftool_conflict_cnt}" == 0)); then
				echo "Looks like only non-bpftool files have conflicts, ignoring..."
				if (("${conflict_cnt}" == 0)); then
					echo "Empty cherry-pick, skipping it..."
					git cherry-pick --abort
					continue
				fi

				git add .
				# GIT_EDITOR=true to avoid editor popping up to edit commit message
				if ! GIT_EDITOR=true git cherry-pick --continue &>/dev/null; then
					echo "Error! That still failed! Please resolve manually."
				else
					echo "Success! All cherry-pick conflicts were resolved for '${desc}'!"
					prompt_resolution=0
				fi
			fi

			if (("${prompt_resolution}" == 1)); then
				read -rp "Error! Cherry-picking '${desc}' failed, please fix manually and press <return> to proceed..."
			fi
		fi
		echo "LINUX_$(git log --pretty='%h' -n1) ${signature}" >> "${TMP_DIR}"/bpftool_commits.txt
	done
}

cleanup()
{
	echo "Cleaning up..."
	rm -r -- "${TMP_DIR}"
	cd_to "${LINUX_REPO}"
	git checkout "${TIP_SYM_REF}"
	git branch -D "${BASELINE_TAG}" "${TIP_TAG}" "${BPF_BASELINE_TAG}" "${BPF_TIP_TAG}" \
		      "${SQUASH_BASE_TAG}" "${SQUASH_TIP_TAG}" || true
	# shellcheck disable=SC2015
	git show-ref --verify --quiet refs/heads/"${VIEW_TAG}" && \
		git branch -D "${VIEW_TAG}" || true

	cd_to .
	echo "DONE."
}