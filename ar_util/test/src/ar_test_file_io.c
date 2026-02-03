/*
*  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
*  SPDX-License-Identifier: BSD-3-Clause
*/
#include <stdio.h>
#include "ar_osal_file_io.h"
#include "ar_osal_error.h"
#include "ar_osal_types.h"
#include "ar_osal_test.h"
#include "ar_osal_log.h"

int32_t ar_osal_test_file_write(const char_t *file, uint32_t file_access, void *write_data, size_t data_size)
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_written = 0;

	/* open file*/
	status = ar_fopen(&fhandle, file, file_access);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to open the file %s:error:%d ", file, status);
		goto end;
	}

	/* write into file */
	AR_LOG_INFO(LOG_TAG, "write data: %s", write_data);

	/* write data */
	status = ar_fwrite(fhandle, write_data, data_size, &bytes_written);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to write into the file %d ", status);
		goto end;
	}
	if (bytes_written != data_size)
	{
		//print
		AR_LOG_INFO(LOG_TAG, "failed write file size not matching ");
	}

end:
	if (fhandle)
	{
		// close file
		status = ar_fclose(fhandle);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG, "failed to close file %d ", status);
		}
	}
	return status;
}

int32_t ar_osal_test_file_read(const char_t *file, uint32_t file_access, void *read_data, size_t read_size, size_t *bytes_read)
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;

	status = ar_fopen(&fhandle, file, file_access);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to open the file:%s:error:%d ", file, status);
		goto end;
	}

	/* read data */
	status = ar_fread(fhandle, read_data, read_size, bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to read the file %d ", status);
		goto end;
	}

end:
	if (fhandle)
	{
		// close file
		status = ar_fclose(fhandle);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG, "failed to close file %d ", status);
		}
	}
	return status;
}


void ar_test_file_read_only()
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_read = 0;
	char_t data_read[50] = { 0 };
	char_t data[] = "File read only test";
	char_t *file = "read_only_file.txt";

	status = ar_fopen(&fhandle, file, AR_FOPEN_READ_ONLY);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to open the file:%s:error:%d for read (**expected) ", file, status);
	}

	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data, sizeof(data));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	status = ar_osal_test_file_read(file, AR_FOPEN_READ_ONLY, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY error:%d ", status);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
end:
	ar_fdelete(file);
	return;
}

void ar_test_file_write_only()
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_read = 0;
	char_t data_read[50] = { 0 };
	char_t data[] = "File write only test";
	char_t *file = "write_only_file.txt";

	// write data first time.
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data, sizeof(data));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	//write data second time
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data, sizeof(data));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	status = ar_osal_test_file_read(file, AR_FOPEN_READ_ONLY, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY error:%d ", status);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
	AR_LOG_INFO(LOG_TAG, "AR_FOPEN_WRITE_ONLY data size(%d)|bytes_read(%d)", sizeof(data), bytes_read);

	if (bytes_read != sizeof(data))
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_WRITE_ONLY Operation");
	}

end:
	ar_fdelete(file);
	return;
}

void ar_test_file_write_only_append()
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_read = 0;
	char_t data[] = "File write only append test";
	char_t data_read[2* sizeof(data)] = { 0 };
	char_t *file = "write_only_append_file.txt";

	// write data firs time.
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data, sizeof(data));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	//write data second time
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY_APPEND, data, sizeof(data));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	status = ar_osal_test_file_read(file, AR_FOPEN_READ_ONLY, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY error:%d ", status);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
	AR_LOG_INFO(LOG_TAG, "AR_FOPEN_WRITE_ONLY_APPEND data size(%d)|bytes_read(%d)", (2*sizeof(data)), bytes_read);

	if (bytes_read != (2* sizeof(data)))
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_WRITE_ONLY_APPEND Operation");
	}

end:
	ar_fdelete(file);
	return;
}

void ar_test_file_read_write_append()
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_read = 0;
	char_t data1[] = "File read write append test 1";
	char_t data2[] = "File read write append test 2";
	char_t data_read[2 * sizeof(data1)] = { 0 };
	char_t *file = "read_write_append_file.txt";

	// write data first time.
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data1, sizeof(data1));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	//Append data now.
	status = ar_osal_test_file_write(file, AR_FOPEN_READ_WRITE_APPEND, data2, sizeof(data2));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	//read the data now.
	status = ar_osal_test_file_read(file, AR_FOPEN_READ_WRITE_APPEND, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_WRITE_APPEND error:%d ", status);
		goto end;
	}
	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
	AR_LOG_INFO(LOG_TAG, "AR_FOPEN_READ_WRITE_APPEND data size(%d)|bytes_read(%d)", (2 * sizeof(data2)), bytes_read);

	if (bytes_read != (2 * sizeof(data2)))
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_WRITE_APPEND Operation");
	}

end:
	ar_fdelete(file);
	return;
}

void ar_test_file_read_only_write()
{
	/*file must exists and contents will be overwritten*/
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t bytes_read = 0;
	char_t data1[] = "File read only write test 1";
	char_t data2[] = "File read only write test 2";
	char_t data_read[2 * sizeof(data1)] = { 0 };
	char_t *file = "read_only_write_file.txt";

	status = ar_fopen(&fhandle, file, AR_FOPEN_READ_ONLY_WRITE);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to open the file:%s:error:%d for read only write (**expected) ", file, status);
	}

	// write data first time.
	status = ar_osal_test_file_write(file, AR_FOPEN_WRITE_ONLY, data1, sizeof(data1));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to created a test file error:%d ", status);
		goto end;
	}

	//read the data now.
	status = ar_osal_test_file_read(file, AR_FOPEN_READ_ONLY_WRITE, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY_WRITE error:%d ", status);
		goto end;
	}
	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
	AR_LOG_INFO(LOG_TAG, "AR_FOPEN_READ_ONLY_WRITE data size(%d)|bytes_read(%d)", sizeof(data1), bytes_read);

	if (bytes_read != sizeof(data1))
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY_WRITE Operation");
	}

	// write data again.
	status = ar_osal_test_file_write(file, AR_FOPEN_READ_ONLY_WRITE, data2, sizeof(data2));
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to write in AR_FOPEN_READ_ONLY_WRITE serror:%d ", status);
		goto end;
	}

	//read the data again.
	status = ar_osal_test_file_read(file, AR_FOPEN_READ_ONLY_WRITE, data_read, sizeof(data_read), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY_WRITE error:%d ", status);
		goto end;
	}
	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);
	AR_LOG_INFO(LOG_TAG, "AR_FOPEN_READ_ONLY_WRITE data size(%d)|bytes_read(%d)", sizeof(data2), bytes_read);

	if (bytes_read != sizeof(data2))
	{
		AR_LOG_ERR(LOG_TAG, "failed AR_FOPEN_READ_ONLY_WRITE Operation");
	}

end:
	ar_fdelete(file);
	return;
}

void ar_test_file_read_write()
{
	int32_t status = AR_EOK;
	ar_fhandle fhandle = NULL;
	size_t fsize = 0;
	size_t bytes_read = 0;
	size_t bytes_written = 0;
	char_t data1[] = "File read write test 1";
	char_t data2[] = "File read write test 2";
	char_t data_read[2 * sizeof(data1)] = { 0 };
	char_t *file = "read_write_file.txt";

	/* open file*/
	status = ar_fopen(&fhandle, file, AR_FOPEN_READ_WRITE);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to open the file %s:error:%d ", file, status);
		goto end;
	}

	fsize = ar_fsize(NULL);

	fsize = ar_fsize(&fhandle);

	fsize = ar_fsize(fhandle);
	// print fsize
	AR_LOG_INFO(LOG_TAG, "file size %d ", fsize);

	AR_LOG_INFO(LOG_TAG, "write data: %s", data1);
	/* write data */
	status = ar_fwrite(fhandle, data1, sizeof(data1), &bytes_written);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to write into the file %d ", status);
		goto end;
	}
	if (bytes_written != sizeof(data1))
	{
		//print
		AR_LOG_INFO(LOG_TAG, "failed write file size not matching ");
	}
	/* get file size */
	fsize = ar_fsize(fhandle);
	// print fsize
	AR_LOG_INFO(LOG_TAG, "file size after write %d ", fsize);

	/* seek file */
	status = ar_fseek(fhandle, 0, AR_FSEEK_END);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to seek file %d ", status);
		goto end;
	}

	/* seek file */
	status = ar_fseek(fhandle, fsize, AR_FSEEK_BEGIN);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to seek file %d ", status);
		goto end;
	}

	status = ar_fclose(fhandle);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to seek file %d ", status);
		goto end;
	}
	fhandle = NULL;

	/* open file*/
	status = ar_fopen(&fhandle, file, AR_FOPEN_READ_WRITE);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to re-open the file:%s:error:%d ", file, status);
		goto end;
	}

	/* read data */
	status = ar_fread(fhandle, data_read, sizeof(data1), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to read the file %d ", status);
		goto end;
	}
	if (bytes_read != 0)
	{
		AR_LOG_ERR(LOG_TAG, "failed to read the right size bytes_read(%d) expected (0)", bytes_read);
		goto end;
	}

	AR_LOG_INFO(LOG_TAG, "write data: %s", data2);
	/* write data */
	status = ar_fwrite(fhandle, data2, sizeof(data2), &bytes_written);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to write into the file %d ", status);
		goto end;
	}
	if (bytes_written != sizeof(data2))
	{
		//print
		AR_LOG_INFO(LOG_TAG, "failed write file size not matching ");
	}

	status = ar_fclose(fhandle);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to close file %d ", status);
	}
	fhandle = NULL;

	/* open file*/
	status = ar_fopen(&fhandle, file, AR_FOPEN_READ_ONLY);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to re-open the file:%s:error:%d ", file, status);
		goto end;
	}

	/* read data */
	status = ar_fread(fhandle, data_read, sizeof(data2), &bytes_read);
	if (status != AR_EOK)
	{
		AR_LOG_ERR(LOG_TAG, "failed to read the file %d ", status);
		goto end;
	}
	if (bytes_read != sizeof(data2))
	{
		AR_LOG_ERR(LOG_TAG, "failed to read the right size bytes_read(%d) file_data(%d)", bytes_read, sizeof(data2));
		goto end;
	}
	AR_LOG_INFO(LOG_TAG, "read data: %s", data_read);

end:
	if (NULL != fhandle)
	{
		status = ar_fclose(fhandle);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG, "failed to close file %d ", status);
		}
		status = ar_fdelete(file);
		if (status != AR_EOK)
		{
			AR_LOG_ERR(LOG_TAG, "failed to delete file %d ", status);
		}
	}
	return;
}

void ar_test_file_main()
{
	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_read_only********");
	ar_test_file_read_only();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_read_only******** \n ");

	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_write_only********");
	ar_test_file_write_only();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_write_only********\n");

	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_write_only_append********");
	ar_test_file_write_only_append();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_write_only_append********\n");

	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_read_write_append********");
	ar_test_file_read_write_append();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_read_write_append********\n");

	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_read_only_write********");
	ar_test_file_read_only_write();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_read_only_write********\n");

	AR_LOG_INFO(LOG_TAG, "******Test start*******ar_test_file_read_write********");
	ar_test_file_read_write();
	AR_LOG_INFO(LOG_TAG, "******Test end*******ar_test_file_read_write********\n");

	return;
}
