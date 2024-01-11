/*
                                  NETWIB
                             Network library
                Copyright(c) 1999-2012 Laurent CONSTANTIN
                      http://ntwib.sourceforge.net/
                        laurentconstantin@free.fr
                                  -----
  This file is part of Netwib.

  Netwib is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 3
  as published by the Free Software Foundation.

  Netwib is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details (http://www.gnu.org/).

------------------------------------------------------------------------
*/

#include <netwib/inc/maininc.h>

/*-------------------------------------------------------------*/
#include "priv/bufstore.c"

/*-------------------------------------------------------------*/
netwib_err netwib_priv_buf_wipe(netwib_buf *pbuf) {
  if ( (pbuf->flags & NETWIB_BUF_FLAGS_SENSITIVE) &&
      !(pbuf->flags & NETWIB_BUF_FLAGS_SENSITIVE_READONLY)) {
    netwib_c_memset(pbuf->totalptr, 0, pbuf->totalsize);
    pbuf->flags &= ~NETWIB_BUF_FLAGS_SENSITIVE;
    pbuf->flags &= ~NETWIB_BUF_FLAGS_SENSITIVE_READONLY;
  }
  return(NETWIB_ERR_OK);
}
