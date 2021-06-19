/**
 * VB5-6, VBA6-7 types define
 * Import to IDA/Ghidra to analyze VB/VBA binaries
 * RE, analyze, collect, define by HTC - VinCSS (a member of Vingroup)
 * Beerware licenses :D
 */

#pragma once

#if !defined(__VB_VBA_567_H__)
#define __VB_VBA_567_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAKE_TIL    1

#if MAKE_TIL
    #include <windows.h>
    #include <oleauto.h>
    #include <ole2.h>

    #pragma comment(lib, "oleaut32")
    #pragma comment(lib, "ole2")
#endif

//
// VBA enums
//

// VB/VBA error code = Err.Number and Err.Description
// It is input parameter for VB/VBA internal function EbRaiseExceptionCode
enum VBAErrorCode
{
    VBA_RETURN_WITHOUT_SUB = 3,                 // Return without GoSub
    VBA_INVALID_PROCEDURE_CALL = 5,             // Invalid procedure call
    VBA_OVERFLOW = 6,                           // Overflow
    VBA_OUT_OF_MEMORY = 7,                      // Out of memory
    VBA_SUBSCRIPT_OUT_OF_RANGE = 9,             // Subscript out of range
    VBA_ARRAY_FIXED_LOCKED = 10,                // This array is fixed or temporarily locked
    VBA_DIVIDE_BY_ZERO = 11,                    // Division by zero
    VBA_TYPE_MISMATCH = 13,                     // Type mismatch
    VBA_OUT_OF_STRING = 14,                     // Out of string space
    VBA_STACK_OVERFLOW = 16,                    // Stack overflow or Expression too complex
    VBA_REQUEST_OPERATION_ERROR = 17,           // Can't perform requested operation
    VBA_USER_INTERRUPT = 18,                    // User interrupt occurred
    VBA_RESUME_WITHOUT_ERROR = 20,              // Resume without error
    VBA_OUT_OF_STACK = 28,                      // Out of stack space
    VBA_NOT_DEFINED = 35,                       // Sub, Function, or Property not defined
    VBA_OUT_OF_RESOURCE = 47,                   // Too many code resource or DLL application clients
    VBA_LOADING_CODE_DLL_ERROR = 48,            // Error in loading code resource or DLL
    VBA_BAD_CODE_CONVENTION = 49,               // Bad code resource or DLL calling convention
    VBA_INTERNAL_ERROR = 51,                    // Internal error
    VBA_BAD_FILENAME_NUMBER = 52,               // Bad file name or number
    VBA_FILE_NOT_FOUND = 53,                    // File not found
    VBA_BAD_FILE_MODE = 54,                     // Bad file mode
    VBA_FILE_ALREADY_OPEN = 55,                 // File already open
    VBA_DEVICE_IO_ERROR = 57,                   // Device I/O error
    VBA_FILE_ALREADY_EXISTS = 58,               // File already exists
    VBA_BAD_RECORD_LEN = 59,                    // Bad record length
    VBA_DISK_FULL = 61,                         // Disk full
    VBA_INPUT_PAST_EOF = 62,                    // Input past end of file
    VBA_BAD_RECORD_NUM = 63,                    // Bad record number
    VBA_TOO_MANY_FILES = 67,                    // Too many files
    VBA_DEVICE_UNAVAILABLE = 68,                // Device unavailable
    VBA_PERMISSION_DENIED = 70,                 // Permission denied
    VBA_DISK_NOT_READY = 71,                    // Disk not ready
    VBA_RENAME_DIFFERENT_DRIVE = 74,            // Can't rename with different drive
    VBA_PATH_FILE_ACCESS_ERROR = 75,            // Path/File access error
    VBA_PATH_NOT_FOUND = 76,                    // Path not found
    VBA_OBJECT_WITH_NOT_SET = 91,               // Object variable or With block variable not set
    VBA_FOR_NOT_INITIALIZED = 92,               // For loop not initialized
    VBA_INVALID_PATTERN = 93,                   // Invalid pattern string
    VBA_INVALID_USE_NULL = 94,                  // Invalid use of Null
    VBA_CALL_FRIEND_ERROR = 97,                 // Can't call Friend procedure on an object that is not an instance of the defining class
    VBA_INCLUDE_REFERENCE_ERROR = 98,           // A property or method call cannot include a reference to a private object, either as an argument or as a return value
    VBA_SYS_RESOURCE_DLL_LOAD_ERROR = 298,      // System resource or DLL could not be loaded
    VBA_INVALID_CHAR_DEVICE_NAME = 320,         // Can't use character device names in specified file names
    VBA_INVALID_FILE_FORMAT = 321,              // Invalid file format
    VBA_CREATE_TEMP_FILE_ERROR = 322,           // Can’t create necessary temporary file
    VBA_INVALID_RESOURCE_FORMAT = 325,          // Invalid format in resource file
    VBA_DATA_VALUE_NAME_NOT_FOUND = 327,        // Data value named not found
    VBA_WRITE_ARRAYS_ERROR = 328,               // Illegal parameter; can't write arrays
    VBA_ACCESS_SYSTEM_REGISTRY_ERROR = 335,     // Could not access system registry
    VBA_COMPONENT_NOT_REGISTERED = 336,         // Component not correctly registered
    VBA_COMPONENT_NOT_FOUND = 337,              // Component not found
    VBA_COMPONENT_NOT_RUN = 338,                // Component did not run correctly
    VBA_OBJECT_ALREADY_LOADED = 360,            // Object already loaded
    VBA_LOAD_UNLOAD_OBJECT_ERROR = 361,         // Can't load or unload this object
    VBA_CONTROL_SPECIFIED_NOT_FOUND = 363,      // Control specified not found
    VBA_OBJECT_UNLOADED = 364,                  // Object was unloaded
    VBA_UNLOAD_IN_CONTEXT_ERROR = 365,          // Unable to unload within this context
    VBA_FILE_OUT_OF_DATE = 368,                 // The specified file is out of date. This program requires a later version
    VBA_OBJECT_NOT_OWNER = 371,                 // The specified object can't be used as an owner form for Show
    VBA_INVALID_PROPERTY_VALUE = 380,           // Invalid property value
    VBA_INVALID_PROPERTY_ARRAY_INDEX = 381,     // Invalid property-array index
    VBA_PROPERTY_SET_ERROR = 382,               // Property Set can't be executed at run time
    VBA_PROPERTY_READ_ONLY = 383,               // Property Set can't be used with a read-only property
    VBA_NEED_PROPERTY_INDEX = 385,              // Need property-array index
    VBA_PROPERTY_SET_NOT_PERMITTED = 387,       // Property Set not permitted
    VBA_PROPERTY_GET_ERROR = 393,               // Property Get can't be executed at run time
    VBA_PROPERTY_WRITE_ONLY = 394,              // Property Get can't be executed on write-only property
    VBA_FORM_ALREADY_DISPLAYED = 400,           // Form already displayed; can't show modally
    VBA_MUST_CLOSE_TOPMOST_MODAL = 402,         // Code must close topmost modal form first
    VBA_OBJECT_PERMISSION_DENIED = 419,         // Permission to use object denied
    VBA_PROPERTY_NOT_FOUND = 422,               // Property not found
    VBA_METHOD_NOT_FOUND = 423,                 // Property or method not found
    VBA_OBJECT_REQUIRED = 424,                  // Object required
    VBA_INVALID_OBJECT_USE = 425,               // Invalid object use
    VBA_CREATE_OBJECT_ERROR = 429,              // Component can't create object or return reference to this object
    VBA_NOT_SUPPORT_AUTOMATION = 430,           // Class doesn't support Automation
    VBA_AUTOMATION_NAME_NOT_FOUND = 432,        // File name or class name not found during Automation operation
    VBA_PROPETRY_METHOD_NOT_SUPPORT = 438,      // Object doesn't support this property or method
    VBA_AUTOMATION_ERROR = 440,                 // Automation error
    VBA_LIBRARY_CONNECTION_LOST = 442,          // Connection to type library or object library for remote process has been lost
    VBA_OBJECT_NOT_HAVE_DEFAULT_VALUE = 443,    // Automation object doesn't have a default value
    VBA_ACTION_NOT_SUPPORT = 445,               // Object doesn't support this action
    VBA_NAME_ARGS_NOT_SUPPORT = 446,            // Object doesn't support named arguments
    VBA_CURRENT_LOCALE_NOT_SUPPORT = 447,       // Object doesn't support current locale setting
    VBA_NAME_ARG_NOT_FOUND = 448,               // Named argument not found
    VBA_ARG_NOT_OPTIONAL = 449,                 // Argument not optional or invalid property assignment
    VBA_WRONG_NUMBER_ARGS = 450,                // Wrong number of arguments or invalid property assignment
    VBA_OBJECT_NOT_COLLECTION = 451,            // Object not a collection
    VBA_INVALID_ORDINAL = 452,                  // Invalid ordinal
    VBA_SPECIFIED_CODE_NOT_FOUND = 453,         // Specified code resource not found
    VBA_CODE_RESOURCE_NOT_FOUND = 454,          // Code resource not found
    VBA_CODE_LOCK_ERROR = 455,                  // Code resource lock error
    VBA_KEY_ALREADY_ASSOCIATED = 457,           // This key is already associated with an element of this collection
    VBA_TYPE_NOT_SUPPORTED = 458,               // Variable uses a type not supported in Visual Basic
    VBA_SET_EVENTS_NOT_SUPPORT = 459,           // This component doesn't support the set of events
    VBA_INVALID_CLIPBOARD_FORMAT = 460,         // Invalid Clipboard format
    VBA_METHOD_DATA_MEMBER_NOT_FOUND = 461,     // Method or data member not found
    VBA_REMOTE_SERVER_ERROR = 462,              // The remote server machine does not exist or is unavailable
    VBA_CLASS_NOT_REGISTERED = 463,             // Class not registered on local machine
    VBA_CREATE_AUTOREDRAW_ERROR = 480,          // Can't create AutoRedraw image
    VBA_INVALID_PICTURE = 481,                  // Invalid picture
    VBA_PRINTER_ERROR = 482,                    // Printer error
    VBA_PRINTER_PROPERTY_NOT_SUPPORT = 483,     // Printer driver does not support specified property
    VBA_GET_PRINTER_INFORMATION_ERROR = 484,    // Problem getting printer information from the system. Make sure the printer is set up correctly
    VBA_INVALID_PICTURE_TYPE = 485,             // Invalid picture type
    VBA_FORM_IMAGE_PRINT_ERROR = 486,           // Can't print form image to this type of printer
    VBA_VARIABLE_UNDEFINED = 500,               // Variable is undefined
    VBA_OBJ_NOT_SAFE_SCRIPTING = 502,           // Object not safe for scripting
    VBA_OBJ_NOT_SAFE_INITIALIZING = 503,        // Object not safe for initializing
    VBA_OBJ_NOT_SAFE_CREATING = 504,            // Object not safe for creating
    VBA_INVALID_REFERENCE = 505,                // Invalid or unqualified reference
    VBA_CLASS_NOT_DEFINED = 506,                // Class not defined
    VBA_EXCEPTION_OCCURRED = 507,               // An exception occurred
    VBA_EMPTY_CLIPBOARD_ERROR = 520,            // Can't empty Clipboard
    VBA_OPEN_CLIPBOARD_ERROR = 521,             // Can't open Clipboard
    VBA_SAVE_TEMP_FILE_ERROR = 735,             // Can't save file to TEMP directory
    VBA_SEARCH_TEXT_NOT_FOUND = 744,            // Search text not found
    VBA_REPLACEMENTS_TOO_LONG = 746,            // Replacements too long
    VBA_ILLEGAL_ASSIGN = 5008,                  // Illegal assignment
    VBA_REGEX_SYNTAX_ERROR = 5017,              // Syntax error in regular expression
    VBA_UNEXPECTED_QUANTIFIER = 5018,           // Unexpected quantifier
    VBA_EXPECTED_SQUARE_BRACKET = 5019,         // Expected ']' in regular expression
    VBA_EXPECTED_ROUND_BRACKET = 5020,          // Expected ')' in regular expression
    VBA_INVALID_RANGE_CHAR_SET = 5021,          // Invalid range in character set
    VBA_OUT_OF_HEAP_MEMORY = 31001,             // Out of heap memory
    VBA_OBJECT_CLIPBOARD_ERROR = 31003,
    VBA_NO_OBJECT = 31004,                      // No object
    VBA_OBJECT_NOT_STILL_ON_CLIPBOARD = 31007,
    VBA_INVALID_CLIPBOARD_FORMAT_NAME = 31008,
    // 31017: Unknown
    VBA_CLASS_NOT_SET = 31018,                  // Class is not set
    VBA_INVALID_VB_CLSID = 31023,               // Invalid VB CLSID from ProgID
    VBA_INVALID_FILE_PATH = 31026,              // Invalid file path
    VBA_UNABLE_ACTIVATE_OBJECT = 31027,         // Unable to activate object
    VBA_OBJECT_NOT_RUNNING = 31028,
    VBA_INVALID_MONIKER_SYNTAX = 31031,
    VBA_UNABLE_CREATE_EMBEDDED_OBJECT = 31032,  // Unable to create embedded object
    VBA_SAVE_FILE_ERROR = 31036,                // Error saving to file
    VBA_LOAD_FILE_ERROR = 31037,                // Error loading from file
    VBA_FILE_NOT_EXISTED = 31039,               // File not existed
    VBA_vbObjectError = 0x80040000,
    // 31029, 31033, 31035 = ???
};

enum VBA_Calendar
{
    vbCalGreg = 0,  // Indicates that the Gregorian calendar is used.
    vbCalHijri = 1, // Indicates that the Hijri calendar is used.
};

enum VBA_CallType
{
    vbMethod = 1,   // Indicates that a method has been invoked.
    vbGet = 2,      // Indicates a Property Get procedure.
    vbLet = 4,      // Indicates a Property Let procedure.
    vbSet = 8,      // Indicates a Property Set procedure.
};

enum VBA_Color
{
    vbBlack   = 0x0,        // Black
    vbRed     = 0xFF,       // Red
    vbGreen   = 0xFF00,     // Green
    vbYellow  = 0xFFFF,     // Yellow
    vbBlue    = 0xFF0000,   // Blue
    vbMagenta = 0xFF00FF,   // Magenta
    vbCyan    = 0xFFFF00,   // Cyan
    vbWhite   = 0xFFFFFF    // White
};

enum VBA_Comparison
{
    vbUseCompareOption = -1,    // Performs a comparison using the setting of the Option Compare statement.
    vbBinaryCompare = 0,        // Performs a binary comparison.
    vbTextCompare = 1,          // Performs a textual comparison.
    vbDatabaseCompare = 2,      // For Microsoft Access (Windows only), performs a comparison based on information contained in your database.
};

enum VBA_Date_FirstDayOfWeek
{
    vbUseSystem = 0,    // Use NLS API setting.
    vbSunday = 1,       // Sunday (default)
    vbMonday = 2,       // Monday
    vbTuesday = 3,      // Tuesday
    vbWednesday = 4,    // Wednesday
    vbThursday = 5,     // Thursday
    vbFriday = 6,       // Friday
    vbSaturday = 7,     // Saturday
};

enum VBA_Date_FirstDayOfYear
{
    VbUseSystemDayOfWeek = 0,   // Use the day of the week specified in your system settings for the first day of the week.
    VbFirstJan1 = 1,            // Start with week in which January 1 occurs (default).
    vbFirstFourDays = 2,        // Start with the first week that has at least four days in the new year.
    vbFirstFullWeek = 3,        // Start with the first full week of the year.
};

enum VBA_Date_Format
{
    vbGeneralDate = 0,  // Display a date and/or time. For real numbers, display a data and time. If there is no fractional part, display only a date. If there is no integer part, display time only. Date and time display is determined by your system settings.
    vbLongDate = 1,     // Display a date using the long date format specified in your computer's regional settings.
    vbShortDate = 2,    // Display a date using the short date format specified in your computer's regional settings.
    vbLongTime = 3,     // Display a time using the long time format specified in your computer's regional settings.
    vbShortTime = 4,    // Display a time using the short time format specified in your computer's regional settings.
};

enum VBA_Dir_Attr
{
    vbNormal = 0,       // Normal (default for Dir and SetAttr)
    vbReadOnly = 1,     // Read-only
    vbHidden = 2,       // Hidden
    vbSystem = 4,       // System file
    vbVolume = 8,       // Volume label
    vbDirectory = 16,   // Directory or folder
    vbArchive = 32,     // File has changed since last backup
    vbAlias = 64,       // On the Macintosh, identifier is an alias.
};

enum VBA_DriveType
{
    _Unknown = 0,       // Drive type can't be determined.
    Removable = 1,      // Drive has removable media. This includes all floppy drives and many other varieties of storage devices.
    Fixed = 2,          // Drive has fixed (nonremovable) media. This includes all hard drives, including hard drives that are removable.
    Remote = 3,         // Network drives. This includes drives shared anywhere on a network.
    CDROM = 4,          // Drive is a CD-ROM. No distinction is made between read-only and read/write CD-ROM drives.
    RAMDisk = 5,        // Drive is a block of Random Access Memory (RAM) on the local computer that behaves like a disk drive.
};

enum VBA_FileAttr
{
    Normal = 0,         // Normal file. No attributes are set.
    ReadOnly = 1,       // Read-only file. Attribute is read/write.
    Hidden = 2,         // Hidden file. Attribute is read/write.
    System = 4,         // System file. Attribute is read/write.
    Volume = 8,         // Disk drive volume label. Attribute is read-only.
    Directory = 16,     // Folder or directory. Attribute is read-only.
    Archive = 32,       // File has changed since last backup. Attribute is read/write.
    Alias = 64,         // Link or shortcut. Attribute is read-only.
    Compressed = 128,   // Compressed file. Attribute is read-only.
};

enum VBA_FileIO
{
    ForReading = 1,     // Open a file for reading only. You can't write to this file.
    ForWriting = 2,     // Open a file for writing. If a file with the same name exists, its previous contents are overwritten.
    ForAppending = 8,   // Open a file and write to the end of the file.
};

enum VBA_FormShow
{
    vbModeless = 0,     // UserForm is modeless.
    vbModal = 1,        // UserForm is modal (default).
};

enum VBA_IMEStatus
{
    vbIMEModeNoControl = 0,     // Don't control IME (default)
    vbIMEModeOn = 1,            // IME on
    vbIMEModeOff = 2,           // IME off
    vbIMEModeDisable = 3,       // IME disabled
    vbIMEModeHiragana = 4,      // Full-width Hiragana mode
    vbIMEModeKatakana = 5,      // Full-width Katakana mode
    vbIMEModeKatakanaHalf = 6,  // Half-width Katakana mode
    vbIMEModeAlphaFull = 7,     // Full-width Alphanumeric mode
    vbIMEModeAlpha = 8,         // Half-width Alphanumeric mode
    vbIMEModeHangulFull = 9,    // Full-width Hangul mode
    vbIMEModeHangul = 10,       // Half-width Hangul mode
};

enum VBA_Keycode
{
    vbKeyLButton = 0x1,         // Left mouse button
    vbKeyRButton = 0x2,         // Right mouse button
    vbKeyCancel = 0x3,          // CANCEL key
    vbKeyMButton = 0x4,         // Middle mouse button
    vbKeyBack = 0x8,            // BACKSPACE key
    vbKeyTab = 0x9,             // TAB key
    vbKeyClear = 0xC,           // CLEAR key
    vbKeyReturn = 0xD,          // ENTER key
    vbKeyShift = 0x10,          // SHIFT key
    vbKeyControl = 0x11,        // CTRL key
    vbKeyMenu = 0x12,           // MENU key
    vbKeyPause = 0x13,          // PAUSE key
    vbKeyCapital = 0x14,        // CAPS LOCK key
    vbKeyEscape = 0x1B,         // ESC key
    vbKeySpace = 0x20,          // SPACEBAR key
    vbKeyPageUp = 0x21,         // PAGE UP key
    vbKeyPageDown = 0x22,       // PAGE DOWN key
    vbKeyEnd = 0x23,            // END key
    vbKeyHome = 0x24,           // HOME key
    vbKeyLeft = 0x25,           // LEFT ARROW key
    vbKeyUp = 0x26,             // UP ARROW key
    vbKeyRight = 0x27,          // RIGHT ARROW key
    vbKeyDown = 0x28,           // DOWN ARROW key
    vbKeySelect = 0x29,         // SELECT key
    vbKeyPrint = 0x2A,          // PRINT SCREEN key
    vbKeyExecute = 0x2B,        // EXECUTE key
    vbKeySnapshot = 0x2C,       // SNAPSHOT key
    vbKeyInsert = 0x2D,         // INSERT key
    vbKeyDelete = 0x2E,         // DELETE key
    vbKeyHelp = 0x2F,           // HELP key
    vbKeyNumlock = 0x90,        // NUM LOCK key

    // ASCII equivalents A – Z
    vbKeyA = 65,                // A key
    vbKeyB = 66,                // B key
    vbKeyC = 67,                // C key
    vbKeyD = 68,                // D key
    vbKeyE = 69,                // E key
    vbKeyF = 70,                // F key
    vbKeyG = 71,                // G key
    vbKeyH = 72,                // H key
    vbKeyI = 73,                // I key
    vbKeyJ = 74,                // J key
    vbKeyK = 75,                // K key
    vbKeyL = 76,                // L key
    vbKeyM = 77,                // M key
    vbKeyN = 78,                // N key
    vbKeyO = 79,                // O key
    vbKeyP = 80,                // P key
    vbKeyQ = 81,                // Q key
    vbKeyR = 82,                // R key
    vbKeyS = 83,                // S key
    vbKeyT = 84,                // T key
    vbKeyU = 85,                // U key
    vbKeyV = 86,                // V key
    vbKeyW = 87,                // W key
    vbKeyX = 88,                // X key
    vbKeyY = 89,                // Y key
    vbKeyZ = 90,                // Z key

    // Number 0 - 9:
    vbKey0 = 48,                // 0 key
    vbKey1 = 49,                // 1 key
    vbKey2 = 50,                // 2 key
    vbKey3 = 51,                // 3 key
    vbKey4 = 52,                // 4 key
    vbKey5 = 53,                // 5 key
    vbKey6 = 54,                // 6 key
    vbKey7 = 55,                // 7 key
    vbKey8 = 56,                // 8 key
    vbKey9 = 57,                // 9 key

    // Numeric keypad:
    vbKeyNumpad0 = 0x60,        // 0 key
    vbKeyNumpad1 = 0x61,        // 1 key
    vbKeyNumpad2 = 0x62,        // 2 key
    vbKeyNumpad3 = 0x63,        // 3 key
    vbKeyNumpad4 = 0x64,        // 4 key
    vbKeyNumpad5 = 0x65,        // 5 key
    vbKeyNumpad6 = 0x66,        // 6 key
    vbKeyNumpad7 = 0x67,        // 7 key
    vbKeyNumpad8 = 0x68,        // 8 key
    vbKeyNumpad9 = 0x69,        // 9 key
    vbKeyMultiply = 0x6A,       // MULTIPLICATION SIGN (*) key
    vbKeyAdd = 0x6B,            // PLUS SIGN (+) key
    vbKeySeparator = 0x6C,      // ENTER key
    vbKeySubtract = 0x6D,       // MINUS SIGN (–) key
    vbKeyDecimal = 0x6E,        // DECIMAL POINT (.) key
    vbKeyDivide = 0x6F,         // DIVISION SIGN (/) key

    // Function keys:
    vbKeyF1 = 0x70,             // F1 key
    vbKeyF2 = 0x71,             // F2 key
    vbKeyF3 = 0x72,             // F3 key
    vbKeyF4 = 0x73,             // F4 key
    vbKeyF5 = 0x74,             // F5 key
    vbKeyF6 = 0x75,             // F6 key
    vbKeyF7 = 0x76,             // F7 key
    vbKeyF8 = 0x77,             // F8 key
    vbKeyF9 = 0x78,             // F9 key
    vbKeyF10 = 0x79,            // F10 key
    vbKeyF11 = 0x7A,            // F11 key
    vbKeyF12 = 0x7B,            // F12 key
    vbKeyF13 = 0x7C,            // F13 key
    vbKeyF14 = 0x7D,            // F14 key
    vbKeyF15 = 0x7E,            // F15 key
    vbKeyF16 = 0x7F,            // F16 key
};

enum VBA_MsgBox_Args
{
    vbOKOnly = 0,                   // OK button only (default)
    vbOKCancel = 1,                 // OK and Cancel buttons
    vbAbortRetryIgnore = 2,         // Abort, Retry, and Ignore buttons
    vbYesNoCancel = 3,              // Yes, No, and Cancel buttons
    vbYesNo = 4,                    // Yes and No buttons
    vbRetryCancel = 5,              // Retry and Cancel buttons
    vbCritical = 16,                // Critical message
    vbQuestion = 32,                // Warning query
    vbExclamation = 48,             // Warning message
    vbInformation = 64,             // Information message
    vbDefaultButton1 = 0,           // First button is default (default)
    vbDefaultButton2 = 256,         // Second button is default
    vbDefaultButton3 = 512,         // Third button is default
    vbDefaultButton4 = 768,         // Fourth button is default
    vbApplicationModal = 0,         // Application modal message box (default)
    vbSystemModal = 4096,           // System modal message box
    vbMsgBoxHelpButton = 16384,     // Adds Help button to the message box
    VbMsgBoxSetForeground = 65536,  // Specifies the message box window as the foreground window
    vbMsgBoxRight = 524288,         // Text is right aligned
    vbMsgBoxRtlReading = 1048576,   // Specifies text should appear as right-to-left reading on Hebrew and Arabic systems
};

enum VBA_MsgBox_Return
{
    vbOK = 1,                   // OK button pressed
    vbCancel = 2,               // Cancel button pressed
    vbAbort = 3,                // Abort button pressed
    vbRetry = 4,                // Retry button pressed
    vbIgnore = 5,               // Ignore button pressed
    vbYes = 6,                  // Yes button pressed
    vbNo = 7,                   // No button pressed
};

enum VBA_QueryClose
{
    vbFormControlMenu = 0,      // The user chose the Close command from the Control menu on the form.
    vbFormCode = 1,             // The Unload statement is invoked from code.
    vbAppWindows = 2,           // The current Microsoft Windows operating environment session is ending.
    vbAppTaskManager = 3,       // The Windows Task Manager is closing the application.
};

enum VBA_Shell
{
    vbHide = 0,                 // Window is hidden and focus is passed to the hidden window.
    vbNormalFocus = 1,          // Window has focus and is restored to its original size and position.
    vbMinimizedFocus = 2,       // Window is displayed as an icon with focus.
    vbMaximizedFocus = 3,       // Window is maximized with focus.
    vbNormalNoFocus = 4,        // Window is restored to its most recent size and position. The currently active window remains active.
    vbMinimizedNoFocus = 6,     // Window is displayed as an icon. The currently active window remains active.
};

enum VBA_SpecialFolder
{
    WindowsFolder = 0,          // The Windows folder contains files installed by the Windows operating system.
    SystemFolder = 1,           // The System folder contains libraries, fonts, and device drivers.
    TemporaryFolder = 2,        // The Temp folder is used to store temporary files. Its path is found in the TMP environment variable.
};

enum VBA_StrConv
{
    vbUpperCase = 1,            // Converts the string to uppercase characters.
    vbLowerCase = 2,            // Converts the string to lowercase characters.
    vbProperCase = 3,           // Converts the first letter of every word in string to uppercase.
    vbWide = 4,                 // Converts narrow (single-byte) characters in string to wide (double-byte) characters. Applies to East Asia locales.
    vbNarrow = 8,               // Converts wide (double-byte) characters in string to narrow (single-byte) characters. Applies to East Asia locales.
    vbKatakana = 16,            // Converts Hiragana characters in string to Katakana characters. Applies to Japan only.
    vbHiragana = 32,            // Converts Katakana characters in string to Hiragana characters. Applies to Japan only.
    vbUnicode = 64,             // Converts the string to Unicode using the default code page of the system. (Not available on the Macintosh.)
    vbFromUnicode = 128,        // Converts the string from Unicode to the default code page of the system. (Not available on the Macintosh.)
};

enum VBA_SystemColor
{
    vbScrollBars = 0x80000000,              // Scroll bar color
    vbDesktop = 0x80000001,                 // Desktop color
    vbActiveTitleBar = 0x80000002,          // Color of the title bar for the active window
    vbInactiveTitleBar = 0x80000003,        // Color of the title bar for the inactive window
    vbMenuBar = 0x80000004,                 // Menu background color
    vbWindowBackground = 0x80000005,        // Window background color
    vbWindowFrame = 0x80000006,             // Window frame color
    vbMenuText = 0x80000007,                // Color of text on menus
    vbWindowText = 0x80000008,              // Color of text in windows
    vbTitleBarText = 0x80000009,            // Color of text in caption, size box, and scroll arrow
    vbActiveBorder = 0x8000000A,            // Border color of active window
    vbInactiveBorder = 0x8000000B,          // Border color of inactive window
    vbApplicationWorkspace = 0x8000000C,    // Background color of multiple-document interface (MDI) applications
    vbHighlight = 0x8000000D,               // Background color of items selected in a control
    vbHighlightText = 0x8000000E,           // Text color of items selected in a control
    vbButtonFace = 0x8000000F,              // Color of shading on the face of command buttons
    vbButtonShadow = 0x80000010,            // Color of shading on the edge of command buttons
    vbGrayText = 0x80000011,                // Grayed (disabled) text
    vbButtonText = 0x80000012,              // Text color on push buttons
    vbInactiveCaptionText = 0x80000013,     // Color of text in an inactive caption
    vb3DHighlight = 0x80000014,             // Highlight color for 3-D display elements
    vb3DDKShadow = 0x80000015,              // Darkest shadow color for 3-D display elements
    vb3DLight = 0x80000016,                 // Second lightest 3-D color after vb3DHighlight
    vbInfoText = 0x80000017,                // Color of text in ToolTips
    vbInfoBackground = 0x80000018,          // Background color of ToolTips
};

enum VBA_Tristate
{
    vbTrue = -1,        // True
    vbFalse = 0,        // False
    vbUseDefault = -2,  // Use default setting
};

enum VBA_VarType    // = VARENUM in VARIANT.vt
{
    vbEmpty = 0,                // Uninitialized (default), = VT_EMPTY
    vbNull = 1,                 // Contains no valid data, = VT_NULL
    vbInteger = 2,              // Integer, = VT_I2
    vbLong = 3,                 // Long integer, = VT_I4
    vbSingle = 4,               // Single-precision floating-point number, = VT_R4
    vbDouble = 5,               // Double-precision floating-point number, = VT_R8
    vbCurrency = 6,             // Currency, = VT_CY
    vbDate = 7,                 // Date,= VT_DATE
    vbString = 8,               // String, = VT_BSTR
    vbObject = 9,               // Object (IDispatch), = VT_DISPATCH
    vbError = 10,               // Error, = VT_ERROR
    vbBoolean = 11,             // Boolean, = VT_BOOL
    vbVariant = 12,             // Variant (used only for arrays of variants), = VT_VARIANT
    vbDataObject = 13,          // Data access object (IUnknown), = VT_UNKNOWN
    vbDecimal = 14,             // Decimal, = VT_DECIMAL
    vbByte = 17,                // Byte, = VT_UI1
    vbUserDefinedType = 36,     // Variants that contain user-defined types, = VT_RECORD
    vbArray = 8192,             // Array, = 0x2000 = VT_ARRAY
};

//
// VB/VBA data types
//

// Byte: stored as  single, unsigned, 8-bit (1-byte) numbers ranging in value from 0–255; VT_UI1
typedef BYTE VBA_Byte;

// Boolean: stored as short 16-bit (2-byte) numbers, True = -1, False = 0; VT_BOOL
typedef VARIANT_BOOL VBA_Boolean;

// Integer: stored as 16-bit (2-byte) numbers ranging in value from -32,768 to 32,767, VT_I2
typedef SHORT VBA_Integer;

// Long: stored as signed 32-bit (4-byte) numbers ranging in value from -2,147,483,648 to 2,147,483,647; VT_I4
typedef LONG VBA_Long;

#if defined(_WIN64)
    // LongLong: stored as signed 64-bit (8-byte) numbers ranging in value from -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807,
    // only on 64-bit platforms
    typedef QWORD VBA_LongLong;
    typedef VBA_LongLong VBA_LongPtr;
#else
    typedef LONG VBA_LongPtr;
#endif

// Single: stored as IEEE 32-bit (4-byte) floating-point numbers, VT_R4
typedef FLOAT VBA_Single;

// Double: stored as IEEE 64-bit (8-byte) floating-point numbers, VT_R8
typedef DOUBLE VBA_Double;

// Currency: stored as 64-bit (8-byte) numbers in an integer format, scaled by 10,000 to give a fixed-point number
// with 15 digits to the left of the decimal point and 4 digits to the right, VT_CY
typedef CURRENCY VBA_Currency;  // = CY struct

// Decimal: stored as signed 128-bit (16-byte) values representing 96-bit (12-byte) integer numbers scaled by a
// variable power of 10. The scaling factor specifies the number of digits to the right of the decimal point;
// it ranges from 0 through 28. Decimal data type can only be used within a Variant; VT_DECIMAL
typedef DECIMAL VBA_Decimal;

// Date:  stored as IEEE 64-bit (8-byte) floating-point numbers that represent dates
// ranging from 1 January 100 to 31 December 9999 and times from 0:00:00 to 23:59:59; VT_DATE
typedef DATE VBA_Date;

// Object: stored as IDispatch * or inherited from IDispatch, VT_DISPATCH
typedef LPDISPATCH VBA_Object;

// String:
//  - fixed string: LPSTR (char *), can contain 1 to approximately 64K (2^16) characters
//  - variable-length string: BSTR, can contain up to approximately 2 billion (2^31) characters
typedef BSTR VBA_String;

// Variant: same as VARIANT (= VARIANTARG)
typedef VARIANT VBA_Variant;

// Array: SAFEARRAY *, VT_ARRAY
typedef LPSAFEARRAY VBA_Array;

// User define type (UDT): stored as a VARIANT with vt = VT_RECORD and __tagBRECORD data member
typedef VARIANT VBA_Record;

#pragma pack(push, 8)

// Internal VB/VBA structs

// DllFunctionCall structs
//
typedef struct
{
    DWORD dwErrCode;
    HMODULE hModule;
    FARPROC pFunction;
} epiDllTemplateInfo;

typedef struct
{
    LPCSTR pszModuleName;   // Dll name
    LPCSTR pszFunctionName; // Function name
    WORD wOrdinal;
    WORD wPadding;
    epiDllTemplateInfo *pDllTemplateInfo;
} serDllTemplate;

// Error structs
struct ERRMSG
{
    LPSTR pszErrMsg;
    DWORD m_dw1;
    DWORD m_dw2;
};

struct ERRINFO
{
    LPSTR pszErrMsg;
    DWORD m_dw1;
    DWORD m_dw2;
    DWORD m_dw3;
    DWORD m_dw4;
};

#pragma pack(pop)

//
// VB/VBA export functions
//

#define VBAIMP __declspec(dllimport)


#ifdef __cplusplus
}   // extern "C"
#endif

// to be continues

#endif  // __VB_VBA_567_H__
