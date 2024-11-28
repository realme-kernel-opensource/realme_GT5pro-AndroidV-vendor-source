// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#ifndef __ES4G_ASSIST_H__
#define __ES4G_ASSIST_H__

#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <kernel/sched/sched.h>

#define MAX_NR_CPUS					(1 << 3)
#ifdef MAX_TASK_NR
#define MAX_KEY_THREAD_RECORD		((MAX_TASK_NR + 1) >> 1)
#else
#define MAX_KEY_THREAD_RECORD		MAX_NR_CPUS
#endif /* MAX_TASK_NR */
#define MAX_KEY_THREAD_PRIORITY		(0)
#define MAX_KEY_THREAD_PRIORITY_US	(MAX_KEY_THREAD_PRIORITY + 1)
#define MIN_KEY_THREAD_PRIORITY		(8)
#define KEY_THREAD_PRIORITY_COUNT	(MIN_KEY_THREAD_PRIORITY - MAX_KEY_THREAD_PRIORITY + 1)
#define ONE_PAGE_SIZE				(1 << 5)
#define KEY_THREAD_FLAG				(1 << 3)

#define DEBUG_SYSTRACE				(1 << 0)
#define DEBUG_FTRACE				(1 << 1)

#define SLIM_FOR_SGAME			(1 << 0)
#define SLIM_FOR_GENSHIN		(1 << 1)
extern int slim_for_app;

enum es4g_ctrl_cmd_id {
	ES4G_FIRST_ID, /* reserved word */
	ES4G_DEBUG_LEVEL,
	ES4G_SET_CRITICAL_TASK,
	ES4G_SELECT_CPU_LIST,
	ES4G_SET_ISOLATE_CPUS,
	ES4G_MAX_ID,
};

struct es4g_ctrl_info
{
	s64 data[ONE_PAGE_SIZE];
	size_t size;
};

#define ES4G_MAGIC 0xE0
#define CMD_ID_ES4G_DEBUG_LEVEL \
	_IOWR(ES4G_MAGIC, ES4G_DEBUG_LEVEL, struct es4g_ctrl_info)
#define CMD_ID_ES4G_SET_CRITICAL_TASK \
	_IOWR(ES4G_MAGIC, ES4G_SET_CRITICAL_TASK, struct es4g_ctrl_info)
#define CMD_ID_ES4G_SELECT_CPU_LIST \
	_IOWR(ES4G_MAGIC, ES4G_SELECT_CPU_LIST, struct es4g_ctrl_info)
#define CMD_ID_ES4G_SET_ISOLATE_CPUS \
	_IOWR(ES4G_MAGIC, ES4G_SET_ISOLATE_CPUS, struct es4g_ctrl_info)

int es4g_assist_init(void);
void es4g_assist_exit(void);

#endif /* __ES4G_ASSIST_H__ */
