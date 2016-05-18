package nachos.userprog;

import nachos.machine.*;
import nachos.threads.*;
import nachos.userprog.*;

import java.io.EOFException;

/**
 * Encapsulates the state of a user process that is not contained in its user
 * thread (or threads). This includes its address translation state, a file
 * table, and information about the program being executed.
 * 
 * <p>
 * This class is extended by other classes to support additional functionality
 * (such as additional syscalls).
 * 
 * @see nachos.vm.VMProcess
 * @see nachos.network.NetProcess
 */
public class UserProcess {
	/**
	 * Allocate a new process.
	 */
	public UserProcess() {
		pageTable = new TranslationEntry[numPages];

		// initialize stdin and stdout for each process
		fileTable = new OpenFile[maxOpenFiles];
		fileTable[fdStandardInput] = UserKernel.console.openForReading();
		fileTable[fdStandardOutput] = UserKernel.console.openForWriting();
		filesOpen = minOpenFiles;

		// increment UserKernel's processCounter and add to processMap
	}

	/**
	 * Allocate and return a new process of the correct class. The class name is
	 * specified by the <tt>nachos.conf</tt> key
	 * <tt>Kernel.processClassName</tt>.
	 * 
	 * @return a new process of the correct class.
	 */
	public static UserProcess newUserProcess() {
		return (UserProcess) Lib.constructObject(Machine.getProcessClassName());
	}

	/**
	 * Execute the specified program with the specified arguments. Attempts to
	 * load the program, and then forks a thread to run it.
	 * 
	 * @param name the name of the file containing the executable.
	 * @param args the arguments to pass to the executable.
	 * @return <tt>true</tt> if the program was successfully executed.
	 */
	public boolean execute(String name, String[] args) {
		if (!load(name, args))
			return false;

		new UThread(this).setName(name).fork();

		return true;
	}

	/**
	 * Save the state of this process in preparation for a context switch.
	 * Called by <tt>UThread.saveState()</tt>.
	 */
	public void saveState() {
	}

	/**
	 * Restore the state of this process after a context switch. Called by
	 * <tt>UThread.restoreState()</tt>.
	 */
	public void restoreState() {
		Machine.processor().setPageTable(pageTable);
	}

	/**
	 * Read a null-terminated string from this process's virtual memory. Read at
	 * most <tt>maxLength + 1</tt> bytes from the specified address, search for
	 * the null terminator, and convert it to a <tt>java.lang.String</tt>,
	 * without including the null terminator. If no null terminator is found,
	 * returns <tt>null</tt>.
	 * 
	 * @param vaddr the starting virtual address of the null-terminated string.
	 * @param maxLength the maximum number of characters in the string, not
	 * including the null terminator.
	 * @return the string read, or <tt>null</tt> if no null terminator was
	 * found.
	 */
	public String readVirtualMemoryString(int vaddr, int maxLength) {
		Lib.assertTrue(maxLength >= 0);

		byte[] bytes = new byte[maxLength + 1];

		int bytesRead = readVirtualMemory(vaddr, bytes);

		for (int length = 0; length < bytesRead; length++) {
			if (bytes[length] == 0)
				return new String(bytes, 0, length);
		}

		return null;
	}

	/**
	 * Transfer data from this process's virtual memory to all of the specified
	 * array. Same as <tt>readVirtualMemory(vaddr, data, 0, data.length)</tt>.
	 * 
	 * @param vaddr the first byte of virtual memory to read.
	 * @param data the array where the data will be stored.
	 * @return the number of bytes successfully transferred.
	 */
	public int readVirtualMemory(int vaddr, byte[] data) {
		return readVirtualMemory(vaddr, data, 0, data.length);
	}

	/**
	 * Transfer data from this process's virtual memory to the specified array.
	 * This method handles address translation details. This method must
	 * <i>not</i> destroy the current process if an error occurs, but instead
	 * should return the number of bytes successfully copied (or zero if no data
	 * could be copied).
	 * 
	 * @param vaddr the first byte of virtual memory to read.
	 * @param data the array where the data will be stored.
	 * @param offset the first byte to write in the array.
	 * @param length the number of bytes to transfer from virtual memory to the
	 * array.
	 * @return the number of bytes successfully transferred.
	 */
	public int readVirtualMemory(int vaddr, byte[] data, int offset, int length) {
		Lib.assertTrue(offset >= 0 && length >= 0
				&& offset + length <= data.length);
		byte[] memory = Machine.processor().getMemory();

		if (vaddr < 0 || vaddr >= memory.length)
			return 0;

		int vpn = Processor.pageFromAddress(vaddr);
		int addressOffset = Processor.offsetFromAddress(vaddr);

		if(pageTable[vpn] == null || !pageTable[vpn].valid || vpn >= pageTable.length)
			return 0;

		int ppn = pageTable[vpn].ppn;
		int paddr = pageSize * ppn + addressOffset;

		int amount = Math.min(length, pageSize - addressOffset);
		System.arraycopy(memory, vaddr, data, offset, amount);

		return amount;
	}

	/**
	 * Transfer all data from the specified array to this process's virtual
	 * memory. Same as <tt>writeVirtualMemory(vaddr, data, 0, data.length)</tt>.
	 * 
	 * @param vaddr the first byte of virtual memory to write.
	 * @param data the array containing the data to transfer.
	 * @return the number of bytes successfully transferred.
	 */
	public int writeVirtualMemory(int vaddr, byte[] data) {
		return writeVirtualMemory(vaddr, data, 0, data.length);
	}

	/**
	 * Transfer data from the specified array to this process's virtual memory.
	 * This method handles address translation details. This method must
	 * <i>not</i> destroy the current process if an error occurs, but instead
	 * should return the number of bytes successfully copied (or zero if no data
	 * could be copied).
	 * 
	 * @param vaddr the first byte of virtual memory to write.
	 * @param data the array containing the data to transfer.
	 * @param offset the first byte to transfer from the array.
	 * @param length the number of bytes to transfer from the array to virtual
	 * memory.
	 * @return the number of bytes successfully transferred.
	 */
	public int writeVirtualMemory(int vaddr, byte[] data, int offset, int length) {
		Lib.assertTrue(offset >= 0 && length >= 0
				&& offset + length <= data.length);
		byte[] memory = Machine.processor().getMemory();

		if (vaddr < 0 || vaddr >= memory.length)
			return 0;

		int vpn = Processor.pageFromAddress(vaddr);
		int addressOffset = Processor.offsetFromAddress(vaddr);

		if(pageTable[vpn] == null || !pageTable[vpn].valid || vpn >= pageTable.length)
			return 0;

		int ppn = pageTable[vpn].ppn;
		int paddr = pageSize * ppn + addressOffset;

		int amount = Math.min(length, pageSize - addressOffset);
		System.arraycopy(data, offset, memory, vaddr, amount);

		return amount;
	}

	/**
	 * Load the executable with the specified name into this process, and
	 * prepare to pass it the specified arguments. Opens the executable, reads
	 * its header information, and copies sections and arguments into this
	 * process's virtual memory.
	 * 
	 * @param name the name of the file containing the executable.
	 * @param args the arguments to pass to the executable.
	 * @return <tt>true</tt> if the executable was successfully loaded.
	 */
	private boolean load(String name, String[] args) {
		Lib.debug(dbgProcess, "UserProcess.load(\"" + name + "\")");

		OpenFile executable = ThreadedKernel.fileSystem.open(name, false);
		if (executable == null) {
			Lib.debug(dbgProcess, "\topen failed");
			return false;
		}

		try {
			coff = new Coff(executable);
		}
		catch (EOFException e) {
			executable.close();
			Lib.debug(dbgProcess, "\tcoff load failed");
			return false;
		}

		// make sure the sections are contiguous and start at page 0
		numPages = 0;
		for (int s = 0; s < coff.getNumSections(); s++) {
			CoffSection section = coff.getSection(s);
			if (section.getFirstVPN() != numPages) {
				coff.close();
				Lib.debug(dbgProcess, "\tfragmented executable");
				return false;
			}
			numPages += section.getLength();
		}

		// make sure the argv array will fit in one page
		byte[][] argv = new byte[args.length][];
		int argsSize = 0;
		for (int i = 0; i < args.length; i++) {
			argv[i] = args[i].getBytes();
			// 4 bytes for argv[] pointer; then string plus one for null byte
			argsSize += 4 + argv[i].length + 1;
		}
		if (argsSize > pageSize) {
			coff.close();
			Lib.debug(dbgProcess, "\targuments too long");
			return false;
		}

		// program counter initially points at the program entry point
		initialPC = coff.getEntryPoint();

		// next comes the stack; stack pointer initially points to top of it
		numPages += stackPages;
		initialSP = numPages * pageSize;

		// and finally reserve 1 page for arguments
		numPages++;

		// initialize size of pageTable
		pageTable = new TranslationEntry[numPages];

		if (!loadSections())
			return false;

		// store arguments in last page
		int entryOffset = (numPages - 1) * pageSize;
		int stringOffset = entryOffset + args.length * 4;

		this.argc = args.length;
		this.argv = entryOffset;

		for (int i = 0; i < argv.length; i++) {
			byte[] stringOffsetBytes = Lib.bytesFromInt(stringOffset);
			Lib.assertTrue(writeVirtualMemory(entryOffset, stringOffsetBytes) == 4);
			entryOffset += 4;
			Lib.assertTrue(writeVirtualMemory(stringOffset, argv[i]) == argv[i].length);
			stringOffset += argv[i].length;
			Lib.assertTrue(writeVirtualMemory(stringOffset, new byte[] { 0 }) == 1);
			stringOffset += 1;
		}

		return true;
	}

	/**
	 * Allocates memory for this process, and loads the COFF sections into
	 * memory. If this returns successfully, the process will definitely be run
	 * (this is the last step in process initialization that can fail).
	 * 
	 * @return <tt>true</tt> if the sections were successfully loaded.
	 */
	protected boolean loadSections() {
		if (numPages > UserKernel.freePages.size()) {
			coff.close();
			Lib.debug(dbgProcess, "\tinsufficient physical memory");
			return false;
		}

		int vpn = 0;
		int ppn = 0;
		int lastVpn = 0;
		boolean valid;
		boolean readOnly;
		
		UserKernel.pageListLock.acquire();

		// load sections
		for (int s = 0; s < coff.getNumSections(); s++) {
			CoffSection section = coff.getSection(s);

			Lib.debug(dbgProcess, "\tinitializing " + section.getName()
					+ " section (" + section.getLength() + " pages)");

			// allocate physical pages and fill in page table entry
			for (int i = 0; i < section.getLength(); i++) {
				vpn = section.getFirstVPN() + i;
				ppn = (int) UserKernel.freePages.removeFirst();

				// load vpn into ppn
				section.loadPage(i, ppn);
				pageTable[vpn] = new TranslationEntry(vpn, ppn, true, 
					section.isReadOnly(), false, false);
			}
		}

		// create page entry for stack and arguments
		for (int i = vpn; i < pageTable.length; i++) {
			ppn = (int) UserKernel.freePages.removeFirst();
			pageTable[i] = new TranslationEntry(i, ppn, true, false, false, false);
		}

		UserKernel.pageListLock.release();

		return true;
	}

	/**
	 * Release any resources allocated by <tt>loadSections()</tt>.
	 */
	protected void unloadSections() {		
		UserKernel.pageListLock.acquire();
		
		// put pages back into free memory
		for(int i = 0; i < pageTable.length; i++) {
			UserKernel.freePages.add((Integer) pageTable[i].ppn);
		}

		UserKernel.pageListLock.release();
	}

	/**
	 * Initialize the processor's registers in preparation for running the
	 * program loaded into this process. Set the PC register to point at the
	 * start function, set the stack pointer register to point at the top of the
	 * stack, set the A0 and A1 registers to argc and argv, respectively, and
	 * initialize all other registers to 0.
	 */
	public void initRegisters() {
		Processor processor = Machine.processor();

		// by default, everything's 0
		for (int i = 0; i < processor.numUserRegisters; i++)
			processor.writeRegister(i, 0);

		// initialize PC and SP according
		processor.writeRegister(Processor.regPC, initialPC);
		processor.writeRegister(Processor.regSP, initialSP);

		// initialize the first two argument registers to argc and argv
		processor.writeRegister(Processor.regA0, argc);
		processor.writeRegister(Processor.regA1, argv);
	}

	/**
	 * Handle the halt() system call.
	 * Halt Nachos machine by calling Machine.halt(). Only root 
	 * process (executed by UserKernel.java) should be allowed 
	 * to execute this syscall. Any other process should ignore 
	 * and return immediately.
	 */
	private int handleHalt() {

		Machine.halt();

		Lib.assertNotReached("Machine.halt() did not halt machine!");
		return 0;
	}

	/**
	 * File Manage syscalls: creat, open, read, write, close, unlink
	 * 
	 * A file descriptor is a small, positive int refering to file or stream
	 * (console input, output, network connection). File descriptor can be
	 * passed to read() and write() to read/write to corresponding file/stream.
	 * File descriptor can passed to close() to release file descriptor and associated
	 * resources.
	 */

	/**
	 * Handle the creat() system call.
	 *
	 * Attempt to open named disk file - create if does not exist and return file
	 * descriptor used to access file. creat() can only be used to create file on disk
	 * 
	 * Param is just address of first char of string
	 * Returns new file descriptor or -1 if error. FD should not be stream.
	 */
	private int handleCreat(int vaddr) {
		// check that virtual address is valid in memory
		if(vaddr < 0 || vaddr > pageSize * numPages)
			return -1;
		int fd = -1;

		// read from virtual memory to string
		String name = readVirtualMemoryString(vaddr, maxNameLength);

		// check param valid and number of files doesn't exceed max
		if (name == null || filesOpen >= maxOpenFiles)
			return -1;

		// loop through indices to first uninitialized address
		for(int i = minOpenFiles; i < maxOpenFiles; i++) {
			// open file or create if not already there; update number of files/fd
			if(fileTable[i] == null) {
				fileTable[i] = ThreadedKernel.fileSystem.open(name, true);
				filesOpen++;
				fd = i;

				// file could not be opened
				if(fileTable[i] == null) {
					filesOpen--;
					fd = -1;
				}			
				break;
			}
		}

		return fd;
	}

	/**
	 * Handle the open() system call.
	 *
	 * Attempt to open named disk file and return a file descriptor. Should not
	 * create if does not exist.
	 * 
	 * Param is just address of first char of string
	 * Returns new file descriptor or -1 if error. FD should not be stream.
	 */
	private int handleOpen(int vaddr) {
		// check that virtual address is valid in memory
		if(vaddr < 0 || vaddr > pageSize * numPages)
			return -1;
		int fd = -1;

		// read from virtual memory to string
		String name = readVirtualMemoryString(vaddr, maxNameLength);

		// check param valid and number of files doesn't exceed max
		if (name == null || filesOpen >= maxOpenFiles)
			return -1;

		// loop through indices to first uninitialized address
		for(int i = minOpenFiles; i < maxOpenFiles; i++) {
			// open file or create if not already there; update number of files/fd
			if(fileTable[i] == null) {
				fileTable[i] = ThreadedKernel.fileSystem.open(name, false);
				filesOpen++;
				fd = i;

				// file could not be opened
				if(fileTable[i] == null) {
					filesOpen--;
					fd = -1;
				}
				break;
			}
		}

		return fd;
	}


	/**
	 * Handle the read() system call.
	 *
	 * Read up to count bytes into buffer from file/stream of fd. Does not wait if not full.
	 * 
	 * On success, number of bytes read is returned. If fd = file on disk, file
	 * position advanced by this number.
	 * 
	 * Not necessarily error if returned number less than number bytes requested.
	 * If fd = file on disk, EOF reached. If fd = stream, fewer bytes actually available
	 * than were requested, but more may become available in future.
	 *
	 * On error, -1 returned and new file position undefined. Can happen if fd invalid,
	 * if part of buffer read-only/invalid, or if stream terminated + no more data
	 */
	private int handleRead(int fd, int bufferAddress, int count) {
		// error - fd or buffer address invalid
		if(fd < 0 || fd >= maxOpenFiles || bufferAddress < 0 ||
			count > pageSize * numPages)
			return -1;

		// find initial starting page of stack to count properly
		stackPageStart = numPages - stackPages;
		if(count > ((stackPages - stackPageStart) * pageSize) || count < 0)
			return -1;

		// allocate buffer + other variables for reading
		byte[] localBuffer = new byte[bufSize];
		int bytesRead = 0;
		int readResult = bufSize;
		int writeResult = readResult;

		// read page by page until count reached or bytes less than max bufSize read
		while(bytesRead < count && readResult == bufSize) {
			readResult = fileTable[fd].read(localBuffer, bytesRead, bufSize);
			if(readResult == -1) { return -1; }

			// write into inputted buffer
			writeResult = writeVirtualMemory(bufferAddress, localBuffer, 
				bytesRead, readResult);
			if(readResult != writeResult || writeResult == -1) { return -1; }
			bytesRead += readResult;
		}

		return bytesRead;
	}

	/**
	 * Handle the write() system call.
	 *
	 * Write up to count bytes from buffer into file/stream of fd. Can block but
	 * not guaranteed, might flush to file/stream.
	 * 
	 * On success, number of bytes written is returned and file position advanced. 
	 * ERROR if number returned smaller than number requested. If error happens on
	 * disk file, then disk full. If stream, then stream terminated early.
	 *
	 * On error, -1 returned, new file position undefined. Can happen if fd invalid,
	 * if part of buffer invalid, or if stream terminated.
	 */
	private int handleWrite(int fd, int bufferAddress, int count) {
		// error - fd or buffer address invalid
		if(fd < 0 || fd >= maxOpenFiles || bufferAddress < 0 ||
			(bufferAddress + count) > pageSize * numPages)
			return -1;

		// find initial starting page of stack to count properly
		stackPageStart = numPages - stackPages;
		if(count > ((stackPages - stackPageStart) * pageSize) || count < 0)
			return -1;

		// allocate buffer + other variables for writing
		byte[] localBuffer = new byte[bufSize];
		int bytesRead = 0;
		int readResult = 0;
		int writeResult = 0;

		// read page by page until count reached or bytes less than max bufSize read
		while(bytesRead < count || readResult != bufSize) {
			readResult = readVirtualMemory(bufferAddress, localBuffer, 
				bytesRead, bufSize);
			if(readResult == -1) { return -1; }

			// write into inputted buffer
			writeResult = fileTable[fd].write(localBuffer, bytesRead, readResult);
			if(readResult != writeResult || writeResult == -1) { return -1; }
			bytesRead += readResult;
		}

		return bytesRead;
	}

	/**
	 * Handle the close() system call.
     *
     * Close a fd so it no longer refers to any file/stream and can be reused.
     *
     * If fd refers to file, all data written by write() will be flushed to
     * disk before close() returns.
     * Else stream - all data written to it by write() will eventually be flushed
     * but not necessarily before close() returns.
     *
     * Resources associated with fd released. Returns 0 if succesful or -1 for error.
	 */
	private int handleClose(int fd) {
		if(fd < 0 || fd >= maxOpenFiles)
			return -1;

		// close file and update file table status
		fileTable[fd].close();
		fileTable[fd] = null;
		filesOpen--;
		return 0;
	}

	/**
	 * Handle the unlink() system call.
	 *
	 * Delete file from file system. If no processes have file open, file deletes
	 * immediately, space it was using is made available for reuse.
	 *
	 * If process has file open, file remains in existence until last fd referring
	 * to it is closed. creat() and open() will not be able to return new file
	 * descriptors for file until deleted.
	 *
	 * Returns 0 on success, -1 if error
	 */
	private int handleUnlink(int vaddr) {
		// check that virtual address is valid in memory
		if(vaddr < 0 || vaddr > pageSize * numPages)
			return -1;

		// read from virtual memory to string
		String name = readVirtualMemoryString(vaddr, maxNameLength);
		if (name == null)
			return -1;

		// attempt to remove existing file
		boolean removed = ThreadedKernel.fileSystem.remove(name);
		return (removed) ? 0 : -1;
	}

	private static final int syscallHalt = 0, syscallExit = 1, syscallExec = 2,
			syscallJoin = 3, syscallCreate = 4, syscallOpen = 5,
			syscallRead = 6, syscallWrite = 7, syscallClose = 8,
			syscallUnlink = 9;

	/**
	 * Handle a syscall exception. Called by <tt>handleException()</tt>. The
	 * <i>syscall</i> argument identifies which syscall the user executed:
	 * 
	 * <table>
	 * <tr>
	 * <td>syscall#</td>
	 * <td>syscall prototype</td>
	 * </tr>
	 * <tr>
	 * <td>0</td>
	 * <td><tt>void halt();</tt></td>
	 * </tr>
	 * <tr>
	 * <td>1</td>
	 * <td><tt>void exit(int status);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>2</td>
	 * <td><tt>int  exec(char *name, int argc, char **argv);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>3</td>
	 * <td><tt>int  join(int pid, int *status);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>4</td>
	 * <td><tt>int  creat(char *name);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>5</td>
	 * <td><tt>int  open(char *name);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>6</td>
	 * <td><tt>int  read(int fd, char *buffer, int size);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>7</td>
	 * <td><tt>int  write(int fd, char *buffer, int size);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>8</td>
	 * <td><tt>int  close(int fd);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>9</td>
	 * <td><tt>int  unlink(char *name);</tt></td>
	 * </tr>
	 * </table>
	 * 
	 * @param syscall the syscall number.
	 * @param a0 the first syscall argument.
	 * @param a1 the second syscall argument.
	 * @param a2 the third syscall argument.
	 * @param a3 the fourth syscall argument.
	 * @return the value to be returned to the user.
	 */
	public int handleSyscall(int syscall, int a0, int a1, int a2, int a3) {
		switch (syscall) {
		case syscallHalt:
			return handleHalt();
		case syscallCreate:
			return handleCreat(a0);
		case syscallOpen:
			return handleOpen(a0);
		case syscallRead:
			return handleRead(a0, a1, a2);
		case syscallWrite:
			return handleWrite(a0, a1, a2);
		case syscallClose:
			return handleClose(a0);
		case syscallUnlink:
			return handleUnlink(a0);
		default:
			Lib.debug(dbgProcess, "Unknown syscall " + syscall);
			Lib.assertNotReached("Unknown system call!");
		}
		return 0;
	}

	/**
	 * Handle a user exception. Called by <tt>UserKernel.exceptionHandler()</tt>
	 * . The <i>cause</i> argument identifies which exception occurred; see the
	 * <tt>Processor.exceptionZZZ</tt> constants.
	 * 
	 * @param cause the user exception that occurred.
	 */
	public void handleException(int cause) {
		Processor processor = Machine.processor();

		switch (cause) {
		case Processor.exceptionSyscall:
			int result = handleSyscall(processor.readRegister(Processor.regV0),
					processor.readRegister(Processor.regA0),
					processor.readRegister(Processor.regA1),
					processor.readRegister(Processor.regA2),
					processor.readRegister(Processor.regA3));
			processor.writeRegister(Processor.regV0, result);
			processor.advancePC();
			break;

		default:
			Lib.debug(dbgProcess, "Unexpected exception: "
					+ Processor.exceptionNames[cause]);
			Lib.assertNotReached("Unexpected exception");
		}
	}

	/** The program being run by this process. */
	protected Coff coff;

	/** This process's page table. */
	protected TranslationEntry[] pageTable;

	/** The number of contiguous pages occupied by the program. */
	protected int numPages;

	/** The number of pages in the program's stack. */
	protected final int stackPages = 8;

	private int initialPC, initialSP;
	private int argc, argv;
	private static final int pageSize = Processor.pageSize;
	private static final char dbgProcess = 'a';

	// all added variables below
	protected int filesOpen; // number of files currently open
	protected OpenFile[] fileTable; // indices 0 & 1 are streams; null indicates unused
	protected int stackPageStart; // page index where stack starts
	protected int pid; // process id set in UserKernel

	private static final int bufSize = 1024;
	private static final int fdStandardInput = 0;
	private static final int fdStandardOutput = 1;
	private static final int minOpenFiles = 2;
	private static final int maxOpenFiles = 16;
	private static final int maxNameLength = 256;	
}