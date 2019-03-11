/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */
#ifndef _SIMPLE_LMK_H_
#define _SIMPLE_LMK_H_

struct page *simple_lmk_oom_alloc(unsigned int order, int migratetype);
bool simple_lmk_page_in(struct page *page, unsigned int order, int migratetype);

#endif /* _SIMPLE_LMK_H_ */
