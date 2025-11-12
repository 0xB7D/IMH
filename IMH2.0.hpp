#pragma once
// Basic Includes
#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <array>
#include <iostream>
#include <cmath>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

constexpr double PI = 3.14159265358979323846;

#define _MONO 0
#define _IL2CPP 0

namespace IMH
{
	namespace Helpers
	{
		/* Checks if an address is valid */
		inline bool IsValidAddr(uintptr_t address) noexcept { return address && address >= 0x10000 && address < 0x7FFFFFFF0000; }

		/* Checks if a pointer is valid */
		template<typename T>
		inline bool IsValidPtr(T* p_any) { return p_any != nullptr && IsValidAddr(reinterpret_cast<uintptr_t>(p_any)); }
	}

	namespace Module
	{
		/* Gets the base address of the provided module name*/
		inline uintptr_t GetMBA(const char* moduleName = nullptr) noexcept
		{
			if (moduleName == nullptr)
				return reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));

			return reinterpret_cast<uintptr_t>(GetModuleHandleA(moduleName));
		}
	}

	namespace Utils
	{
		/* Reads memory at the provided address */
		template<typename T>
		inline T Read(uintptr_t address) noexcept
		{
			if (!Helpers::IsValidAddr(address))
				return T();

			DWORD oldProtect;
			if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect))
				return T();

			T retValue = NULL;

			try {
				retValue = *reinterpret_cast<T*>(address);
			}
			catch (...)
			{
				VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
				return T();
			}

			VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
		}

		/* Writes memory at the provided address */
		template<typename T>
		inline bool Write(uintptr_t address, T value) noexcept
		{
			if (!Helpers::IsValidAddr(address))
				return false;
			DWORD oldProtect;
			if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect))
				return false;
			try {
				*reinterpret_cast<T*>(address) = value;
			}
			catch (...)
			{
				VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
				return false;
			}
			VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &oldProtect);
			return true;
		}

		inline uintptr_t FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets) noexcept
		{
			if (!ptr || offsets.empty())
				return 0;

			uintptr_t addr = ptr;

			for (unsigned int i = 0; i < offsets.size(); ++i)
			{
				if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(uintptr_t)))
					return 0;

				addr = *reinterpret_cast<uintptr_t*>(addr);

				if (addr == 0 && i != offsets.size() - 1)
					return 0;

				if (i != offsets.size() - 1)
					addr += offsets[i];
				else
					addr += offsets[i];
			}

			return addr;
		}
	}

	namespace Opcode
	{
		/* Writes new opcodes*/
		inline bool WriteOpcode(uintptr_t address, const std::vector<BYTE>& newBytes) noexcept
		{
			if (address == 0 || newBytes.empty())
				return false;

			BYTE* dest = reinterpret_cast<BYTE*>(address);

			DWORD oldProtect = 0;
			size_t size = newBytes.size();

			// Change memory protection if requested
			VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);

			// Copy the new bytes
			std::memcpy(dest, newBytes.data(), size);

			// Restore protection
			VirtualProtect(dest, size, oldProtect, &oldProtect);

			return true;
		}

		inline std::vector<BYTE> ReadOpcode(uintptr_t address, size_t size)
		{
			if (address == 0 || size == 0)
				return {};

			const BYTE* src = reinterpret_cast<const BYTE*>(address);

			std::vector<BYTE> buffer(size);
			std::memcpy(buffer.data(), src, size);

			return buffer;
		}
	}

    namespace String
    {
        // Core string reading functions
        template <size_t N>
        bool WriteBuffer(uintptr_t address, const char* newStr, bool protect = true) noexcept
        {
            if (!Helpers::IsValidAddr(address) || !newStr)
                return false;

            char* dest = reinterpret_cast<char*>(address);
            DWORD oldProtect = 0;

            if (protect && !VirtualProtect(dest, N, PAGE_EXECUTE_READWRITE, &oldProtect))
                return false;

            try {
                memset(dest, 0, N);
                strncpy_s(dest, N, newStr, N - 1);
                dest[N - 1] = '\0';
            }
            catch (...) {
                if (protect) VirtualProtect(dest, N, oldProtect, &oldProtect);
                return false;
            }

            if (protect) VirtualProtect(dest, N, oldProtect, &oldProtect);
            return true;
        }

        template <size_t N>
        std::string ReadBuffer(uintptr_t address) noexcept
        {
            if (!Helpers::IsValidAddr(address))
                return {};

            try {
                const char* src = reinterpret_cast<const char*>(address);
                char buffer[N + 1] = {};
                memcpy(buffer, src, N);
                buffer[N] = '\0';
                return std::string(buffer);
            }
            catch (...) {
                return {};
            }
        }

        // Wide string functions
        template <size_t N>
        bool WriteWideBuffer(uintptr_t address, const wchar_t* newStr, bool protect = true) noexcept
        {
            if (!Helpers::IsValidAddr(address) || !newStr)
                return false;

            wchar_t* dest = reinterpret_cast<wchar_t*>(address);
            DWORD oldProtect = 0;
            SIZE_T byteSize = N * sizeof(wchar_t);

            if (protect && !VirtualProtect(dest, byteSize, PAGE_EXECUTE_READWRITE, &oldProtect))
                return false;

            try {
                memset(dest, 0, byteSize);
                wcsncpy_s(dest, N, newStr, N - 1);
                dest[N - 1] = L'\0';
            }
            catch (...) {
                if (protect) VirtualProtect(dest, byteSize, oldProtect, &oldProtect);
                return false;
            }

            if (protect) VirtualProtect(dest, byteSize, oldProtect, &oldProtect);
            return true;
        }

        template <size_t N>
        std::wstring ReadWideBuffer(uintptr_t address) noexcept
        {
            if (!Helpers::IsValidAddr(address))
                return {};

            try {
                const wchar_t* src = reinterpret_cast<const wchar_t*>(address);
                wchar_t buffer[N + 1] = {};
                wmemcpy(buffer, src, N);
                buffer[N] = L'\0';
                return std::wstring(buffer);
            }
            catch (...) {
                return {};
            }
        }

        // Dynamic string reading with safety
        std::string ReadString(uintptr_t address, size_t maxLength = 256) noexcept
        {
            if (!Helpers::IsValidAddr(address))
                return {};

            try {
                const char* ptr = reinterpret_cast<const char*>(address);

                // Find actual length safely
                size_t actualLength = 0;
                for (size_t i = 0; i < maxLength; ++i) {
                    if (IsBadReadPtr(ptr + i, 1))
                        break;

                    if (ptr[i] == '\0') {
                        actualLength = i;
                        break;
                    }
                    actualLength = i + 1;
                }

                return actualLength > 0 ? std::string(ptr, actualLength) : std::string{};
            }
            catch (...) {
                return {};
            }
        }

        std::wstring ReadWideString(uintptr_t address, size_t maxLength = 256) noexcept
        {
            if (!Helpers::IsValidAddr(address))
                return {};

            try {
                const wchar_t* ptr = reinterpret_cast<const wchar_t*>(address);

                size_t actualLength = 0;
                for (size_t i = 0; i < maxLength; ++i) {
                    if (IsBadReadPtr(ptr + i, sizeof(wchar_t)))
                        break;

                    if (ptr[i] == L'\0') {
                        actualLength = i;
                        break;
                    }
                    actualLength = i + 1;
                }

                return actualLength > 0 ? std::wstring(ptr, actualLength) : std::wstring{};
            }
            catch (...) {
                return {};
            }
        }

        // String conversion utility
        std::string WideToString(const std::wstring& wstr) noexcept
        {
            if (wstr.empty())
                return {};

            try {
                int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (size <= 0)
                    return {};

                std::string result(size - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
                return result;
            }
            catch (...) {
                return {};
            }
        }

        // Validation result structure
        struct StringInfo
        {
            std::string value;
            bool isValid;
            size_t length;
        };

        StringInfo ReadStringInfo(uintptr_t address, size_t maxLength = 256) noexcept
        {
            StringInfo info = { {}, false, 0 };

            std::string str = ReadString(address, maxLength);
            info.value = str;
            info.length = str.length();
            info.isValid = !str.empty();

            return info;
        }
    }

    namespace ByteCodes
    {
        // Existing opcodes
        constexpr BYTE NOP = 0x90;
        constexpr BYTE RET = 0xC3;
        constexpr BYTE CALL = 0xE8;
        constexpr BYTE JMP = 0xE9;
        constexpr BYTE JE = 0x74;
        constexpr BYTE JNE = 0x75;
        constexpr BYTE JG = 0x7F;
        constexpr BYTE JL = 0x7C;
        constexpr BYTE JGE = 0x7D;
        constexpr BYTE JLE = 0x7E;
        constexpr BYTE PUSH = 0x68;

        // Additional common opcodes
        constexpr BYTE POP = 0x58;          // POP register (base, add register number)
        constexpr BYTE MOV_REG_IMM32 = 0xB8; // MOV register, immediate32 (base, add register number)
        constexpr BYTE MOV_EAX_MEM = 0xA1;  // MOV EAX, memory
        constexpr BYTE MOV_MEM_EAX = 0xA3;  // MOV memory, EAX
        constexpr BYTE MOV_RM_R = 0x89;     // MOV r/m, register
        constexpr BYTE MOV_R_RM = 0x8B;     // MOV register, r/m

        // Short jumps (2-byte instructions)
        constexpr BYTE JMP_SHORT = 0xEB;    // JMP short
        constexpr BYTE JZ = 0x74;           // JZ (alias for JE)
        constexpr BYTE JNZ = 0x75;          // JNZ (alias for JNE)
        constexpr BYTE JS = 0x78;           // Jump if sign
        constexpr BYTE JNS = 0x79;          // Jump if not sign
        constexpr BYTE JO = 0x70;           // Jump if overflow
        constexpr BYTE JNO = 0x71;          // Jump if not overflow
        constexpr BYTE JB = 0x72;           // Jump if below (unsigned)
        constexpr BYTE JAE = 0x73;          // Jump if above or equal (unsigned)
        constexpr BYTE JBE = 0x76;          // Jump if below or equal (unsigned)
        constexpr BYTE JA = 0x77;           // Jump if above (unsigned)

        // Arithmetic operations
        constexpr BYTE ADD_AL_IMM8 = 0x04;  // ADD AL, immediate8
        constexpr BYTE ADD_EAX_IMM32 = 0x05; // ADD EAX, immediate32
        constexpr BYTE SUB_AL_IMM8 = 0x2C;  // SUB AL, immediate8
        constexpr BYTE SUB_EAX_IMM32 = 0x2D; // SUB EAX, immediate32
        constexpr BYTE CMP_AL_IMM8 = 0x3C;  // CMP AL, immediate8
        constexpr BYTE CMP_EAX_IMM32 = 0x3D; // CMP EAX, immediate32

        // Stack operations
        constexpr BYTE PUSH_EAX = 0x50;     // PUSH EAX
        constexpr BYTE PUSH_ECX = 0x51;     // PUSH ECX
        constexpr BYTE PUSH_EDX = 0x52;     // PUSH EDX
        constexpr BYTE PUSH_EBX = 0x53;     // PUSH EBX
        constexpr BYTE PUSH_ESP = 0x54;     // PUSH ESP
        constexpr BYTE PUSH_EBP = 0x55;     // PUSH EBP
        constexpr BYTE PUSH_ESI = 0x56;     // PUSH ESI
        constexpr BYTE PUSH_EDI = 0x57;     // PUSH EDI

        constexpr BYTE POP_EAX = 0x58;      // POP EAX
        constexpr BYTE POP_ECX = 0x59;      // POP ECX
        constexpr BYTE POP_EDX = 0x5A;      // POP EDX
        constexpr BYTE POP_EBX = 0x5B;      // POP EBX
        constexpr BYTE POP_ESP = 0x5C;      // POP ESP
        constexpr BYTE POP_EBP = 0x5D;      // POP EBP
        constexpr BYTE POP_ESI = 0x5E;      // POP ESI
        constexpr BYTE POP_EDI = 0x5F;      // POP EDI

        // Function operations
        constexpr BYTE PUSHAD = 0x60;       // Push all general-purpose registers
        constexpr BYTE POPAD = 0x61;        // Pop all general-purpose registers
        constexpr BYTE PUSHFD = 0x9C;       // Push flags register
        constexpr BYTE POPFD = 0x9D;        // Pop flags register
        constexpr BYTE LEAVE = 0xC9;        // Leave (MOV ESP, EBP; POP EBP)
        constexpr BYTE RET_IMM16 = 0xC2;    // RET immediate16
        constexpr BYTE RETN = 0xC3;         // RET near (alias for RET)
        constexpr BYTE RETF = 0xCB;         // RET far

        // Test and logic
        constexpr BYTE TEST_AL_IMM8 = 0xA8; // TEST AL, immediate8
        constexpr BYTE TEST_EAX_IMM32 = 0xA9; // TEST EAX, immediate32
        constexpr BYTE XOR_AL_IMM8 = 0x34;  // XOR AL, immediate8
        constexpr BYTE XOR_EAX_IMM32 = 0x35; // XOR EAX, immediate32

        // Interrupts and special
        constexpr BYTE INT = 0xCD;          // Interrupt
        constexpr BYTE INT3 = 0xCC;         // Breakpoint interrupt
        constexpr BYTE HLT = 0xF4;          // Halt
        constexpr BYTE CLC = 0xF8;          // Clear carry flag
        constexpr BYTE STC = 0xF9;          // Set carry flag
        constexpr BYTE CLI = 0xFA;          // Clear interrupt flag
        constexpr BYTE STI = 0xFB;          // Set interrupt flag
        constexpr BYTE CLD = 0xFC;          // Clear direction flag
        constexpr BYTE STD = 0xFD;          // Set direction flag

        // Prefix bytes
        constexpr BYTE LOCK_PREFIX = 0xF0;  // Lock prefix
        constexpr BYTE REP_PREFIX = 0xF3;   // Repeat prefix
        constexpr BYTE REPNE_PREFIX = 0xF2; // Repeat while not equal prefix
        constexpr BYTE CS_OVERRIDE = 0x2E;  // CS segment override
        constexpr BYTE DS_OVERRIDE = 0x3E;  // DS segment override
        constexpr BYTE ES_OVERRIDE = 0x26;  // ES segment override
        constexpr BYTE FS_OVERRIDE = 0x64;  // FS segment override
        constexpr BYTE GS_OVERRIDE = 0x65;  // GS segment override
        constexpr BYTE SS_OVERRIDE = 0x36;  // SS segment override

		// Basic 
		constexpr BYTE MOV = 0x89;         // MOV r/m32, r32
    }

    namespace Console
    {
        FILE* Initialize(const char* title) noexcept
        {
            AllocConsole();
            SetConsoleTitleA(title);
            FILE* file;
            freopen_s(&file, "CONOUT$", "w", stdout);
            freopen_s(&file, "CONOUT$", "w", stderr);
            freopen_s(&file, "CONIN$", "r", stdin);
            return file;
        }

        void Free(FILE* file) noexcept
        {
            fclose(file);
            FreeConsole();
        }

        void SetTitle(const char* title) noexcept
        {
            SetConsoleTitleA(title);
        }

        void SetColor(const WORD color) noexcept
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
        }

        void SetPosition(const short x, const short y) noexcept
        {
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), { x, y });
        }

        void Clear() noexcept
        {
            system("cls");
        }

        template<typename... T>
        void Print(T... args)
        {
            (std::cout << ... << args) << std::endl;
        }
    }

    namespace Matrix
    {
        struct Matrix4x4
        {
            float m[4][4];
        };

        struct Matrix3x4
        {
            float m[3][4];
        };

        struct Matrix3x3
        {
            float m[3][3];
        };

        struct Matrix2x2
        {
            float m[2][2];
        };
    }

    namespace Vector
    {
        struct Vector2
        {
            float x, y;

            Vector2 operator+(const Vector2& other) const noexcept
            {
                return { x + other.x, y + other.y };
            }

            Vector2 operator-(const Vector2& other) const noexcept
            {
                return { x - other.x, y - other.y };
            }

            Vector2 operator*(const Vector2& other) const noexcept
            {
                return { x * other.x, y * other.y };
            }

            Vector2 operator/(const Vector2& other) const noexcept
            {
                return { x / other.x, y / other.y };
            }

            Vector2 WorldToScreen(const Matrix::Matrix4x4& viewMatrix, const int windowWidth, const int windowHeight) const noexcept
            {
                Vector2 screen;
                screen.x = viewMatrix.m[0][0] * x + viewMatrix.m[0][1] * y + viewMatrix.m[0][3];
                screen.y = viewMatrix.m[1][0] * x + viewMatrix.m[1][1] * y + viewMatrix.m[1][3];
                const float w = viewMatrix.m[3][0] * x + viewMatrix.m[3][1] * y + viewMatrix.m[3][3];
                if (w < 0.01f)
                    return { -1, -1 };
                screen.x /= w;
                screen.y /= w;
                const float width = windowWidth / 2.0f;
                const float height = windowHeight / 2.0f;
                screen.x = width + 0.5f * screen.x * width + 0.5f;
                screen.y = height - 0.5f * screen.y * height + 0.5f;
                return screen;
            }

            Vector2 Transform(const Matrix::Matrix2x2& mat) const noexcept
            {
                return {
                    mat.m[0][0] * x + mat.m[0][1] * y,
                    mat.m[1][0] * x + mat.m[1][1] * y
                };
            }
        };

        struct Vector3
        {
            float x, y, z;

            Vector3 operator+(const Vector3& other) const noexcept
            {
                return { x + other.x, y + other.y, z + other.z };
            }

            Vector3 operator-(const Vector3& other) const noexcept
            {
                return { x - other.x, y - other.y, z - other.z };
            }

            Vector3 operator*(const Vector3& other) const noexcept
            {
                return { x * other.x, y * other.y, z * other.z };
            }

            Vector3 operator/(const Vector3& other) const noexcept
            {
                return { x / other.x, y / other.y, z / other.z };
            }

            bool operator==(const Vector3& other) const noexcept
            {
                if (x == other.x && y == other.y && z == other.z)
                    return true;
                else
                    return false;
            }

            Vector3 WorldToScreen(const Matrix::Matrix4x4& viewMatrix, int windowWidth, int windowHeight) const noexcept
            {
                Vector3 clip;
                clip.x = viewMatrix.m[0][0] * x + viewMatrix.m[0][1] * y + viewMatrix.m[0][2] * z + viewMatrix.m[0][3];
                clip.y = viewMatrix.m[1][0] * x + viewMatrix.m[1][1] * y + viewMatrix.m[1][2] * z + viewMatrix.m[1][3];
                clip.z = viewMatrix.m[2][0] * x + viewMatrix.m[2][1] * y + viewMatrix.m[2][2] * z + viewMatrix.m[2][3];
                float w = viewMatrix.m[3][0] * x + viewMatrix.m[3][1] * y + viewMatrix.m[3][2] * z + viewMatrix.m[3][3];

                if (w < 0.001f)
                    return { -1, -1, 0 };

                clip.x /= w;
                clip.y /= w;
                clip.z /= w;

                Vector3 screen;
                screen.x = (clip.x * 0.5f + 0.5f) * windowWidth;
                screen.y = (1.0f - (clip.y * 0.5f + 0.5f)) * windowHeight;
                screen.z = clip.z;

                return screen;
            }

            Vector3 WorldToScreen(const Matrix::Matrix3x4& viewMatrix, int windowWidth, int windowHeight) const noexcept
            {
                float clipX = viewMatrix.m[0][0] * x + viewMatrix.m[0][1] * y + viewMatrix.m[0][2] * z + viewMatrix.m[0][3];
                float clipY = viewMatrix.m[1][0] * x + viewMatrix.m[1][1] * y + viewMatrix.m[1][2] * z + viewMatrix.m[1][3];
                float clipZ = viewMatrix.m[2][0] * x + viewMatrix.m[2][1] * y + viewMatrix.m[2][2] * z + viewMatrix.m[2][3];
                float clipW = viewMatrix.m[3][0] * x + viewMatrix.m[3][1] * y + viewMatrix.m[3][2] * z + viewMatrix.m[3][3];

                if (clipW < 0.001f)
                    return { -1, -1, 0 };

                clipX /= clipW;
                clipY /= clipW;
                clipZ /= clipW;

                Vector3 screen;
                screen.x = (clipX * 0.5f + 0.5f) * windowWidth;
                screen.y = (1.0f - (clipY * 0.5f + 0.5f)) * windowHeight;
                screen.z = clipZ;

                return screen;
            }

            Vector3 Transform(const Matrix::Matrix3x3& mat) const noexcept
            {
                return {
                    mat.m[0][0] * x + mat.m[0][1] * y + mat.m[0][2] * z,
                    mat.m[1][0] * x + mat.m[1][1] * y + mat.m[1][2] * z,
                    mat.m[2][0] * x + mat.m[2][1] * y + mat.m[2][2] * z
                };
            }
        };

        struct Vector4
        {
            float x, y, z, w;

            Vector4 operator+(const Vector4& other) const noexcept
            {
                return { x + other.x, y + other.y, z + other.z, w + other.w };
            }

            Vector4 operator-(const Vector4& other) const noexcept
            {
                return { x - other.x, y - other.y, z - other.z, w - other.w };
            }

            Vector4 operator*(const Vector4& other) const noexcept
            {
                return { x * other.x, y * other.y, z * other.z, w * other.w };
            }

            Vector4 operator/(const Vector4& other) const noexcept
            {
                return { x / other.x, y / other.y, z / other.z, w / other.w };
            }

            Vector4 operator*(const float value) const noexcept
            {
                return { x * value, y * value, z * value, w * value };
            }

            Vector4 operator/(const float value) const noexcept
            {
                return { x / value, y / value, z / value, w / value };
            }

            Vector4 WorldToScreen(const Matrix::Matrix4x4& viewMatrix, int windowWidth, int windowHeight) const noexcept
            {
                Vector4 clip;
                clip.x = viewMatrix.m[0][0] * x + viewMatrix.m[0][1] * y + viewMatrix.m[0][2] * z + viewMatrix.m[0][3];
                clip.y = viewMatrix.m[1][0] * x + viewMatrix.m[1][1] * y + viewMatrix.m[1][2] * z + viewMatrix.m[1][3];
                clip.z = viewMatrix.m[2][0] * x + viewMatrix.m[2][1] * y + viewMatrix.m[2][2] * z + viewMatrix.m[2][3];
                clip.w = viewMatrix.m[3][0] * x + viewMatrix.m[3][1] * y + viewMatrix.m[3][2] * z + viewMatrix.m[3][3];

                if (clip.w < 0.001f)
                    return { -1, -1, 0, 0 }; // Behind the camera

                // Perspective divide → NDC
                clip.x /= clip.w;
                clip.y /= clip.w;
                clip.z /= clip.w;

                // Map from NDC [-1, 1] → screen [0, width], [0, height]
                Vector4 screen;
                screen.x = (clip.x * 0.5f + 0.5f) * windowWidth;
                screen.y = (1.0f - (clip.y * 0.5f + 0.5f)) * windowHeight; // Flip Y
                screen.z = clip.z; // Depth (0..1)
                screen.w = clip.w; // Keep original W if you need it later
                return screen;
            }
        };

        float GetDistance(const Vector3& src, const Vector3& dst)
        {
            float dx = dst.x - src.x;
            float dy = dst.y - src.y;
            float dz = dst.z - src.z;
            return sqrtf(dx * dx + dy * dy + dz * dz);
        }

        Vector3 CalcAngles(Vector3 src, Vector3 dst)
        {
            Vector3 angles = {};
            Vector3 delta = dst - src;
            float distance = GetDistance(src, dst);

            // Edge case: Avoid division by zero
            if (distance < 0.001f) {
                return Vector3(0.0f, 0.0f, 0.0f);
            }

            angles.x = -atan2f(delta.x, delta.y) * (180.0f / PI) + 180.0f;

            angles.y = asinf(delta.z / distance) * (180.0f / PI);

            angles.z = 0.0f;

            if (angles.x >= 360.0f) angles.x -= 360.0f;
            if (angles.x < 0.0f) angles.x += 360.0f;

            return angles;
        }
    }

    namespace Scanner
    {
        // ----------------------- ASCII pattern compiler -----------------------
        static inline int hexval(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        }
        static void push_byte_token(const std::string& tok, std::vector<uint8_t>& pat, std::vector<uint8_t>& mask) {
            if (tok == "?" || tok == "??") { pat.push_back(0x00); mask.push_back(0x00); return; }
            if (tok.size() != 2) throw std::runtime_error("Bad token: " + tok);
            const char hi = tok[0], lo = tok[1];
            uint8_t p = 0, m = 0;
            if (hi == '?') { /* upper wildcard */ }
            else {
                int v = hexval(hi); if (v < 0) throw std::runtime_error("Bad hex: " + tok);
                p |= static_cast<uint8_t>(v << 4); m |= 0xF0;
            }
            if (lo == '?') { /* lower wildcard */ }
            else {
                int v = hexval(lo); if (v < 0) throw std::runtime_error("Bad hex: " + tok);
                p |= static_cast<uint8_t>(v & 0x0F); m |= 0x0F;
            }
            pat.push_back(p); mask.push_back(m);
        }
        struct MaskedPattern {
            const uint8_t* pat;
            const uint8_t* mask; // per-byte bitmask (0xFF exact, 0xF0 upper-only, 0x0F lower-only, 0x00 wildcard)
            size_t len;
        };
        static MaskedPattern compile_ascii_pattern(const std::string& ascii,
            std::vector<uint8_t>& pat_out,
            std::vector<uint8_t>& mask_out)
        {
            pat_out.clear(); mask_out.clear();
            std::string tok; tok.reserve(4);
            for (size_t i = 0; i < ascii.size();) {
                while (i < ascii.size() && std::isspace(static_cast<unsigned char>(ascii[i]))) ++i;
                if (i >= ascii.size()) break;
                size_t j = i;
                while (j < ascii.size() && !std::isspace(static_cast<unsigned char>(ascii[j]))) ++j;
                tok = ascii.substr(i, j - i);
                for (char& c : tok) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                push_byte_token(tok, pat_out, mask_out);
                i = j;
            }
            if (pat_out.empty()) throw std::runtime_error("Empty ASCII pattern");
            return MaskedPattern{ pat_out.data(), mask_out.data(), pat_out.size() };
        }

        // ----------------------- Horspool (wildcard-aware) -----------------------
        static size_t find_horspool_masked(const uint8_t* hay, size_t n, const MaskedPattern& mp) {
            const size_t m = mp.len;
            if (!m || n < m) return n;
            // Tail: last fully-known byte (mask 0xFF)
            ptrdiff_t tail = -1;
            for (ptrdiff_t i = (ptrdiff_t)m - 1; i >= 0; --i) if (mp.mask[i] == 0xFF) { tail = i; break; }

            if (tail < 0) { // no concrete anchor → linear masked compare
                for (size_t pos = 0; pos <= n - m; ++pos) {
                    size_t j = 0;
                    for (; j < m; ++j) if (((hay[pos + j] ^ mp.pat[j]) & mp.mask[j]) != 0) break;
                    if (j == m) return pos;
                }
                return n;
            }

            std::array<size_t, 256> shift;
            shift.fill(static_cast<size_t>(tail + 1));
            for (size_t i = 0; i < static_cast<size_t>(tail); ++i)
                if (mp.mask[i] == 0xFF) shift[mp.pat[i]] = static_cast<size_t>(tail - i);

            size_t pos = 0;
            while (pos <= n - m) {
                const uint8_t h = hay[pos + tail];
                if (h == mp.pat[tail]) {
                    ptrdiff_t j = (ptrdiff_t)m - 1;
                    for (; j >= 0; --j)
                        if (((hay[pos + j] ^ mp.pat[j]) & mp.mask[j]) != 0) break;
                    if (j < 0) return pos;
                }
                pos += shift[h];
            }
            return n;
        }

        // ----------------------- PE helpers (.text range) -----------------------
        struct Range { uint8_t* base; size_t size; };
        static bool get_text_range(HMODULE mod, Range& out) {
            auto base = reinterpret_cast<uint8_t*>(mod);
            auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

            auto sect = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                const IMAGE_SECTION_HEADER& s = sect[i];
                // section name is not null-terminated; compare up to 8
                if (std::equal(std::begin(".text"), std::end(".text") - 1, reinterpret_cast<const char*>(s.Name))) {
                    out.base = base + s.VirtualAddress;
                    out.size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
                    return true;
                }
            }
            // fallback: whole image (less efficient, but keeps working)
            out.base = base;
            out.size = nt->OptionalHeader.SizeOfImage;
            return true;
        }

        // ----------------------- Module enumeration -----------------------
        static bool iequals(std::string a, std::string b) {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i)
                if (std::toupper((unsigned char)a[i]) != std::toupper((unsigned char)b[i])) return false;
            return true;
        }
        static std::string filename_only(const std::string& path) {
            const char* sep = "\\/";
            size_t pos = path.find_last_of(sep);
            return (pos == std::string::npos) ? path : path.substr(pos + 1);
        }

        // ----------------------- Core scanning -----------------------
        static uintptr_t scan_range(const Range& r, const std::string& ascii) {
            std::vector<uint8_t> pat, mask;
            auto mp = compile_ascii_pattern(ascii, pat, mask);
            size_t off = find_horspool_masked(r.base, r.size, mp);
            return (off == r.size) ? 0 : (reinterpret_cast<uintptr_t>(r.base) + off);
        }

        static uintptr_t scan_module(HMODULE mod, const std::string& ascii) {
            Range r{};
            if (!get_text_range(mod, r)) return 0;
            return scan_range(r, ascii);
        }

        static uintptr_t scan_all_modules(const std::string& ascii) {
            HANDLE proc = GetCurrentProcess();
            HMODULE mods[1024];
            DWORD cbNeeded = 0;
            if (!EnumProcessModules(proc, mods, sizeof(mods), &cbNeeded)) return 0;
            const size_t count = cbNeeded / sizeof(HMODULE);

            // First: main module
            if (count > 0) {
                if (auto addr = scan_module(mods[0], ascii)) return addr;
            }
            // Then: the rest
            for (size_t i = 1; i < count; ++i) {
                if (auto addr = scan_module(mods[i], ascii)) return addr;
            }
            return 0;
        }

        static HMODULE find_module_by_name(std::string name) {
            if (name == "" || iequals(name, "exe") || iequals(name, "self")) return GetModuleHandleW(nullptr);

            HANDLE proc = GetCurrentProcess();
            HMODULE mods[1024];
            DWORD cbNeeded = 0;
            if (!EnumProcessModules(proc, mods, sizeof(mods), &cbNeeded)) return nullptr;
            const size_t count = cbNeeded / sizeof(HMODULE);

            std::string want = filename_only(name);
            for (size_t i = 0; i < count; ++i) {
                char path[MAX_PATH] = {};
                if (GetModuleFileNameExA(proc, mods[i], path, MAX_PATH)) {
                    std::string file = filename_only(path);
                    if (iequals(file, want)) return mods[i];
                }
            }
            // Also allow GetModuleHandleA if it's already loaded by that exact name
            if (HMODULE h = GetModuleHandleA(want.c_str())) return h;
            return nullptr;
        }

        // ----------------------- Public API (your two overloads) -----------------------

        // example : void* addr = reinterpret_cast<void*>(IMH::Scanner::patternscan("48 8B ?? ?? ?? ?? ?? 48 85 C0 74 0A"));
        // example2: void* addr2 = reinterpret_cast<void*>(IMH::Scanner::patternscan("example.dll", "48 8B ?? ?? ?? ?? ?? 48 85 C0 74 0A"));

        inline uintptr_t patternscan(const char* ascii_pattern) {
            if (!ascii_pattern) return 0;
            try { return scan_all_modules(ascii_pattern); }
            catch (...) { return 0; }
        }

        inline uintptr_t patternscan(const char* module_name, const char* ascii_pattern) {
            if (!ascii_pattern) return 0;
            try {
                HMODULE mod = find_module_by_name(module_name ? module_name : "");
                if (!mod) return 0;
                return scan_module(mod, ascii_pattern);
            }
            catch (...) { return 0; }
        }

        inline uintptr_t patternscan(void* base, size_t size, const char* ascii_pattern) {
            if (!base || !size || !ascii_pattern) return 0;
            try {
                Range r{};
                r.base = static_cast<uint8_t*>(base);
                r.size = size;
                return scan_range(r, ascii_pattern);
            }
            catch (...) {
                return 0;
            }
        }
    }
}

#if _MONO

#include <unordered_map>
#include <mutex>
#include <functional>
#include "Minhook/include/MinHook.h"

// -------- opaque mono types --------
typedef struct _MonoDomain           MonoDomain;
typedef struct _MonoAssembly         MonoAssembly;
typedef struct _MonoImage            MonoImage;
typedef struct _MonoClass            MonoClass;
typedef struct _MonoMethod           MonoMethod;
typedef struct _MonoObject           MonoObject;
typedef struct _MonoString           MonoString;
typedef struct _MonoMethodSignature  MonoMethodSignature;
typedef struct _MonoVTable           MonoVTable;
typedef struct _MonoClassField       MonoClassField;
typedef struct _MonoProperty         MonoProperty;
typedef void* gpointer;

// -------- mono api typedefs (core) --------
typedef MonoDomain* (*mono_get_root_domain_t)(void);
typedef void        (*mono_thread_attach_t)(MonoDomain*);
typedef void        (*mono_assembly_foreach_t)(void(*)(MonoAssembly*, void*), void*);
typedef MonoImage* (*mono_assembly_get_image_t)(MonoAssembly*);
typedef const char* (*mono_image_get_name_t)(MonoImage*);
typedef MonoClass* (*mono_class_from_name_t)(MonoImage*, const char*, const char*);
typedef MonoMethod* (*mono_class_get_method_from_name_t)(MonoClass*, const char*, int);
typedef gpointer(*mono_compile_method_t)(MonoMethod*);
typedef MonoMethodSignature* (*mono_method_signature_t)(MonoMethod*);
typedef int         (*mono_signature_get_param_count_t)(MonoMethodSignature*);
typedef const char* (*mono_method_get_name_t)(MonoMethod*);

// -------- domains (added) --------
typedef MonoDomain* (*mono_domain_get_t)(void);
typedef void        (*mono_domain_set_t)(MonoDomain*, bool /*force*/);
typedef void        (*mono_domain_foreach_t)(void(*)(MonoDomain*, void*), void*);
typedef const char* (*mono_domain_get_friendly_name_t)(MonoDomain*);

// -------- optional descriptor-based search --------
typedef void* (*mono_method_desc_new_t)(const char*, int);
typedef MonoMethod* (*mono_method_desc_search_in_image_t)(void*, MonoImage*);
typedef void        (*mono_method_desc_free_t)(void*);

// -------- fields / properties / enumeration --------
typedef MonoClassField* (*mono_class_get_field_from_name_t)(MonoClass*, const char*);
typedef void        (*mono_field_get_value_t)(MonoObject*, MonoClassField*, void*);
typedef void        (*mono_field_set_value_t)(MonoObject*, MonoClassField*, void*);
typedef void        (*mono_field_static_get_value_t)(MonoVTable*, MonoClassField*, void*);
typedef void        (*mono_field_static_set_value_t)(MonoVTable*, MonoClassField*, void*);
typedef MonoVTable* (*mono_class_vtable_t)(MonoDomain*, MonoClass*);
typedef void* (*mono_class_get_fields_t)(MonoClass*, void** /*iter*/);
typedef MonoMethod* (*mono_class_get_methods_t)(MonoClass*, void** /*iter*/);
typedef MonoProperty* (*mono_class_get_property_from_name_t)(MonoClass*, const char*);
typedef MonoMethod* (*mono_property_get_get_method_t)(MonoProperty*);
typedef MonoMethod* (*mono_property_get_set_method_t)(MonoProperty*);

// -------- object / string / utils --------
typedef MonoObject* (*mono_object_new_t)(MonoDomain*, MonoClass*);
typedef void        (*mono_runtime_object_init_t)(MonoObject*);
typedef MonoString* (*mono_string_new_t)(MonoDomain*, const char*);
typedef char* (*mono_string_to_utf8_t)(MonoString*);
typedef void        (*mono_free_t)(void*);
typedef MonoClass* (*mono_object_get_class_t)(MonoObject*);
typedef MonoString* (*mono_object_to_string_t)(MonoObject*, MonoObject**);

// --- invoke & unbox ---
typedef MonoObject* (*mono_runtime_invoke_t)(MonoMethod*, void*, void**, MonoObject**);
typedef void* (*mono_object_unbox_t)(MonoObject*);

// (optional but handy)
typedef MonoClass* (*mono_get_int32_class_t)(void);
typedef MonoClass* (*mono_get_single_class_t)(void);
typedef MonoClass* (*mono_get_double_class_t)(void);
typedef MonoClass* (*mono_get_boolean_class_t)(void);

namespace IMH
{
    namespace MonoEasy
    {
        struct MonoAPI
        {
            // ---- resolved handles ----
            HMODULE hMono{};
            bool ok{ false };
            bool attached{ false };

            // cached scripting domain (Unity child domain)
            MonoDomain* scriptingDomain{};

            // ---- exports (core) ----
            mono_get_root_domain_t              mono_get_root_domain{};
            mono_thread_attach_t                mono_thread_attach{};
            mono_assembly_foreach_t             mono_assembly_foreach{};
            mono_assembly_get_image_t           mono_assembly_get_image{};
            mono_image_get_name_t               mono_image_get_name{};
            mono_class_from_name_t              mono_class_from_name{};
            mono_class_get_method_from_name_t   mono_class_get_method_from_name{};
            mono_compile_method_t               mono_compile_method{};
            mono_method_signature_t             mono_method_signature{};
            mono_signature_get_param_count_t    mono_signature_get_param_count{};
            mono_method_get_name_t              mono_method_get_name{};

            // ---- domains ----
            mono_domain_get_t                   mono_domain_get{};
            mono_domain_set_t                   mono_domain_set{};
            mono_domain_foreach_t               mono_domain_foreach{};
            mono_domain_get_friendly_name_t     mono_domain_get_friendly_name{};

            // ---- descriptor helpers (optional) ----
            mono_method_desc_new_t              mono_method_desc_new{};
            mono_method_desc_search_in_image_t  mono_method_desc_search_in_image{};
            mono_method_desc_free_t             mono_method_desc_free{};

            // ---- fields / properties / enumeration ----
            mono_class_get_field_from_name_t    mono_class_get_field_from_name{};
            mono_field_get_value_t              mono_field_get_value{};
            mono_field_set_value_t              mono_field_set_value{};
            mono_field_static_get_value_t       mono_field_static_get_value{};
            mono_field_static_set_value_t       mono_field_static_set_value{};
            mono_class_vtable_t                 mono_class_vtable{};
            mono_class_get_fields_t             mono_class_get_fields{};
            mono_class_get_methods_t            mono_class_get_methods{};
            mono_class_get_property_from_name_t mono_class_get_property_from_name{};
            mono_property_get_get_method_t      mono_property_get_get_method{};
            mono_property_get_set_method_t      mono_property_get_set_method{};

            // ---- object / strings ----
            mono_object_new_t                   mono_object_new{};
            mono_runtime_object_init_t          mono_runtime_object_init{};
            mono_string_new_t                   mono_string_new{};
            mono_string_to_utf8_t               mono_string_to_utf8{};
            mono_free_t                         mono_free{};
            mono_object_get_class_t             mono_object_get_class{};
            mono_object_to_string_t             mono_object_to_string{};

            // ---- invoke / unbox ----
            mono_runtime_invoke_t               mono_runtime_invoke{};
            mono_object_unbox_t                 mono_object_unbox{};

            // ---- optional primitive class getters ----
            mono_get_int32_class_t              mono_get_int32_class{};
            mono_get_single_class_t             mono_get_single_class{};
            mono_get_double_class_t             mono_get_double_class{};
            mono_get_boolean_class_t            mono_get_boolean_class{};

            // ---- caching ----
            struct KeyImage {
                std::string substr;
                bool operator==(const KeyImage& o) const { return substr == o.substr; }
            };
            struct KeyClass {
                MonoImage* img{};
                std::string ns;
                std::string cls;
                bool operator==(const KeyClass& o) const { return img == o.img && ns == o.ns && cls == o.cls; }
            };
            struct KeyMethod {
                MonoClass* klass{};
                std::string name;
                int argc{};
                bool operator==(const KeyMethod& o) const { return klass == o.klass && name == o.name && argc == o.argc; }
            };
            struct HashKeyImage {
                size_t operator()(const KeyImage& k) const { return std::hash<std::string>()(k.substr); }
            };
            struct HashKeyClass {
                size_t operator()(const KeyClass& k) const {
                    return std::hash<void*>()(k.img)
                        ^ (std::hash<std::string>()(k.ns) << 1)
                        ^ (std::hash<std::string>()(k.cls) << 2);
                }
            };
            struct HashKeyMethod {
                size_t operator()(const KeyMethod& k) const {
                    return std::hash<void*>()(k.klass)
                        ^ (std::hash<std::string>()(k.name) << 1)
                        ^ std::hash<int>()(k.argc);
                }
            };

            std::unordered_map<KeyImage, MonoImage*, HashKeyImage>  imageCache;
            std::unordered_map<KeyClass, MonoClass*, HashKeyClass>  classCache;
            std::unordered_map<KeyMethod, MonoMethod*, HashKeyMethod> methodCache;
            std::mutex cacheMx;

            // ---- helpers ----
            template<class T>
            bool gp(T& fn, const char* name)
            {
                fn = reinterpret_cast<T>(GetProcAddress(hMono, name));
                return fn != nullptr;
            }

            bool Init()
            {
                const char* names[] = { "mono-2.0-bdwgc.dll", "mono.dll", "libmono.dll" };
                for (auto* n : names) {
                    hMono = GetModuleHandleA(n);
                    if (hMono) break;
                }
                if (!hMono) {
                    std::printf("[MonoEasy] mono dll not found\n");
                    return false;
                }

                bool req =
                    gp(mono_get_root_domain, "mono_get_root_domain") &&
                    gp(mono_thread_attach, "mono_thread_attach") &&
                    gp(mono_assembly_foreach, "mono_assembly_foreach") &&
                    gp(mono_assembly_get_image, "mono_assembly_get_image") &&
                    gp(mono_image_get_name, "mono_image_get_name") &&
                    gp(mono_class_from_name, "mono_class_from_name") &&
                    gp(mono_class_get_method_from_name, "mono_class_get_method_from_name") &&
                    gp(mono_compile_method, "mono_compile_method");

                // optional
                gp(mono_method_signature, "mono_method_signature");
                gp(mono_signature_get_param_count, "mono_signature_get_param_count");
                gp(mono_method_get_name, "mono_method_get_name");

                // domains
                gp(mono_domain_get, "mono_domain_get");
                gp(mono_domain_set, "mono_domain_set");
                gp(mono_domain_foreach, "mono_domain_foreach");
                gp(mono_domain_get_friendly_name, "mono_domain_get_friendly_name");

                // descriptors
                gp(mono_method_desc_new, "mono_method_desc_new");
                gp(mono_method_desc_search_in_image, "mono_method_desc_search_in_image");
                gp(mono_method_desc_free, "mono_method_desc_free");

                // fields/properties/enumeration
                gp(mono_class_get_field_from_name, "mono_class_get_field_from_name");
                gp(mono_field_get_value, "mono_field_get_value");
                gp(mono_field_set_value, "mono_field_set_value");
                gp(mono_field_static_get_value, "mono_field_static_get_value");
                gp(mono_field_static_set_value, "mono_field_static_set_value");
                gp(mono_class_vtable, "mono_class_vtable");
                gp(mono_class_get_fields, "mono_class_get_fields");
                gp(mono_class_get_methods, "mono_class_get_methods");
                gp(mono_class_get_property_from_name, "mono_class_get_property_from_name");
                gp(mono_property_get_get_method, "mono_property_get_get_method");
                gp(mono_property_get_set_method, "mono_property_get_set_method");

                // objects/strings
                gp(mono_object_new, "mono_object_new");
                gp(mono_runtime_object_init, "mono_runtime_object_init");
                gp(mono_string_new, "mono_string_new");
                gp(mono_string_to_utf8, "mono_string_to_utf8");
                gp(mono_free, "mono_free");
                gp(mono_object_get_class, "mono_object_get_class");
                gp(mono_object_to_string, "mono_object_to_string");

                // invoke/unbox
                gp(mono_runtime_invoke, "mono_runtime_invoke");
                gp(mono_object_unbox, "mono_object_unbox");

                // primitive class getters
                gp(mono_get_int32_class, "mono_get_int32_class");
                gp(mono_get_single_class, "mono_get_single_class");
                gp(mono_get_double_class, "mono_get_double_class");
                gp(mono_get_boolean_class, "mono_get_boolean_class");

                ok = req;
                if (!ok)
                    std::printf("[MonoEasy] missing required mono exports\n");

                return ok;
            }

            // Wait for mono module to appear (useful if injected early)
            bool InitWithWait(DWORD timeoutMs = 8000, DWORD pollMs = 50)
            {
                const char* names[] = { "mono-2.0-bdwgc.dll", "mono.dll", "libmono.dll" };
                DWORD waited = 0;
                while (waited <= timeoutMs)
                {
                    for (auto* n : names) {
                        if (GetModuleHandleA(n))
                            return Init();
                    }
                    Sleep(pollMs);
                    waited += pollMs;
                }
                std::printf("[MonoEasy] Mono module not found within %u ms\n", timeoutMs);
                return false;
            }

            bool Attach()
            {
                if (!ok) return false;
                if (attached) return true;

                MonoDomain* dom = mono_get_root_domain ? mono_get_root_domain() : nullptr;
                if (!dom) {
                    std::printf("[MonoEasy] mono root domain null\n");
                    return false;
                }
                mono_thread_attach(dom);
                attached = true;
                return true;
            }

            // capture the current (managed) domain as the "scripting" domain
            void CaptureCurrentDomainAsScripting()
            {
                if (mono_domain_get) {
                    scriptingDomain = mono_domain_get();
                    if (mono_domain_get_friendly_name && scriptingDomain) {
                        std::printf("[MonoEasy] Captured scripting domain: %s\n",
                            mono_domain_get_friendly_name(scriptingDomain));
                    }
                }
            }

            // Choose which domain to operate in
            MonoDomain* ActiveDomain()
            {
                if (scriptingDomain) return scriptingDomain;
                if (mono_domain_get) return mono_domain_get();
                return mono_get_root_domain ? mono_get_root_domain() : nullptr;
            }

            // RAII domain switch
            struct DomainGuard {
                MonoAPI* a{};
                MonoDomain* prev{};
                bool didSwitch{ false };
                DomainGuard(MonoAPI* api, MonoDomain* target) : a(api) {
                    if (a && a->mono_domain_get && a->mono_domain_set && target) {
                        prev = a->mono_domain_get();
                        if (prev != target) {
                            a->mono_domain_set(target, /*force=*/false);
                            didSwitch = true;
                        }
                    }
                }
                ~DomainGuard() {
                    if (a && a->mono_domain_set && prev && didSwitch) {
                        a->mono_domain_set(prev, /*force=*/false);
                    }
                }
            };

            // image find (substring match, e.g., "Assembly-CSharp")
            MonoImage* FindImage(const char* nameSubstr)
            {
                if (!nameSubstr || !*nameSubstr)
                    return nullptr;

                {
                    std::lock_guard<std::mutex> lg(cacheMx);
                    auto it = imageCache.find({ nameSubstr });
                    if (it != imageCache.end())
                        return it->second;
                }

                struct Ctx {
                    MonoAPI* a;
                    const char* sub;
                    MonoImage* out;
                } ctx{ this, nameSubstr, nullptr };

                mono_assembly_foreach([](MonoAssembly* assem, void* ud)
                    {
                        auto& c = *reinterpret_cast<Ctx*>(ud);
                        if (c.out) return;
                        MonoImage* img = c.a->mono_assembly_get_image(assem);
                        if (!img) return;
                        const char* nm = c.a->mono_image_get_name(img);
                        if (nm && std::strstr(nm, c.sub))
                            c.out = img;
                    }, &ctx);

                if (ctx.out)
                {
                    std::lock_guard<std::mutex> lg(cacheMx);
                    imageCache[{ nameSubstr }] = ctx.out;
                }
                return ctx.out;
            }

            // ---- high-level: get native address (jit) ----
            void* GetAddress(const char* imageSubstr,
                const char* nameSpace,
                const char* className,
                const char* methodName,
                int paramCount /* -1 any */)
            {
                if (!Attach()) return nullptr;

                MonoImage* img = FindImage(imageSubstr);
                if (!img) {
                    std::printf("[MonoEasy] image '%s' not found\n", imageSubstr);
                    return nullptr;
                }

                MonoClass* k = nullptr;
                {
                    std::lock_guard<std::mutex> lg(cacheMx);
                    auto it = classCache.find({ img, nameSpace ? nameSpace : "", className });
                    if (it != classCache.end()) k = it->second;
                }
                if (!k)
                {
                    k = mono_class_from_name(img, nameSpace ? nameSpace : "", className);
                    if (!k) {
                        std::printf("[MonoEasy] class %s.%s not found\n", nameSpace ? nameSpace : "", className);
                        return nullptr;
                    }
                    std::lock_guard<std::mutex> lg(cacheMx);
                    classCache[{ img, nameSpace ? nameSpace : "", className }] = k;
                }

                MonoMethod* m = nullptr;
                {
                    std::lock_guard<std::mutex> lg(cacheMx);
                    auto it = methodCache.find({ k, methodName, paramCount });
                    if (it != methodCache.end()) m = it->second;
                }
                if (!m)
                {
                    m = mono_class_get_method_from_name(k, methodName, paramCount);
                    if (!m && mono_method_desc_new && mono_method_desc_search_in_image)
                    {
                        char desc[512]{};
                        if (nameSpace && *nameSpace)
                            std::snprintf(desc, sizeof(desc), "%s.%s:%s", nameSpace, className, methodName);
                        else
                            std::snprintf(desc, sizeof(desc), "%s:%s", className, methodName);

                        void* md = mono_method_desc_new(desc, 1);
                        if (md) {
                            m = mono_method_desc_search_in_image(md, img);
                            mono_method_desc_free(md);
                        }
                    }
                    if (!m) {
                        std::printf("[MonoEasy] method %s::%s not found\n", className, methodName);
                        return nullptr;
                    }
                    std::lock_guard<std::mutex> lg(cacheMx);
                    methodCache[{ k, methodName, paramCount }] = m;
                }

                void* addr = mono_compile_method(m);
                if (!addr) {
                    std::printf("[MonoEasy] mono_compile_method returned null\n");
                    return nullptr;
                }

                int pc = -1;
                if (mono_method_signature && mono_signature_get_param_count) {
                    if (auto* sig = mono_method_signature(m))
                        pc = mono_signature_get_param_count(sig);
                }

                std::printf("[MonoEasy] %s.%s::%s (params=%d) @ %p\n",
                    nameSpace ? nameSpace : "", className, methodName, pc, addr);

                return addr;
            }

            // ---- FQN parser: "Image!Namespace.Class:Method/argc" ----
            void* GetAddressFQN(const char* spec)
            {
                if (!spec || !*spec) return nullptr;
                std::string s(spec);

                size_t bang = s.find('!');
                if (bang == std::string::npos) return nullptr;
                std::string img = s.substr(0, bang);
                std::string rest = s.substr(bang + 1);

                int argc = -1;
                size_t slash = rest.rfind('/');
                if (slash != std::string::npos) {
                    argc = std::atoi(rest.substr(slash + 1).c_str());
                    rest = rest.substr(0, slash);
                }

                size_t colon = rest.rfind(':');
                if (colon == std::string::npos) return nullptr;
                std::string left = rest.substr(0, colon);
                std::string mth = rest.substr(colon + 1);

                std::string ns = "";
                std::string cls = left;
                size_t lastDot = left.rfind('.');
                if (lastDot != std::string::npos) {
                    ns = left.substr(0, lastDot);
                    cls = left.substr(lastDot + 1);
                }

                return GetAddress(img.c_str(), ns.c_str(), cls.c_str(), mth.c_str(), argc);
            }

            // ---- raw pointers (no JIT) ----
            MonoClass* GetClassPtr(const char* imageSubstr, const char* nameSpace, const char* className)
            {
                if (!Attach()) return nullptr;
                MonoImage* img = FindImage(imageSubstr);
                if (!img) return nullptr;
                return mono_class_from_name(img, nameSpace ? nameSpace : "", className);
            }

            MonoMethod* GetMethodPtr(const char* imageSubstr,
                const char* nameSpace,
                const char* className,
                const char* methodName,
                int paramCount /* -1 any */)
            {
                MonoClass* k = GetClassPtr(imageSubstr, nameSpace, className);
                if (!k) return nullptr;

                MonoMethod* m = mono_class_get_method_from_name(k, methodName, paramCount);
                if (!m && mono_method_desc_new && mono_method_desc_search_in_image)
                {
                    MonoImage* img = FindImage(imageSubstr);
                    if (!img) return nullptr;

                    char desc[512]{};
                    if (nameSpace && *nameSpace)
                        std::snprintf(desc, sizeof(desc), "%s.%s:%s", nameSpace, className, methodName);
                    else
                        std::snprintf(desc, sizeof(desc), "%s:%s", className, methodName);

                    void* md = mono_method_desc_new(desc, 1);
                    if (md) {
                        m = mono_method_desc_search_in_image(md, img);
                        mono_method_desc_free(md);
                    }
                }
                return m;
            }

            // ---- fields (instance + static) ----
            MonoClassField* GetFieldPtr(MonoClass* klass, const char* fieldName)
            {
                if (!klass || !fieldName || !*fieldName) return nullptr;
                if (!mono_class_get_field_from_name) return nullptr;
                return mono_class_get_field_from_name(klass, fieldName);
            }

            template<typename T>
            bool GetInstanceField(MonoObject* obj, const char* fieldName, T& outValue)
            {
                if (!obj || !mono_object_get_class || !mono_field_get_value) return false;
                MonoClass* k = mono_object_get_class(obj);
                MonoClassField* f = GetFieldPtr(k, fieldName);
                if (!f) return false;
                mono_field_get_value(obj, f, &outValue);
                return true;
            }

            template<typename T>
            bool SetInstanceField(MonoObject* obj, const char* fieldName, const T& value)
            {
                if (!obj || !mono_object_get_class || !mono_field_set_value) return false;
                MonoClass* k = mono_object_get_class(obj);
                MonoClassField* f = GetFieldPtr(k, fieldName);
                if (!f) return false;
                mono_field_set_value(obj, f, (void*)&value);
                return true;
            }

            template<typename T>
            bool GetStaticField(MonoClass* klass, const char* fieldName, T& outValue)
            {
                if (!klass || !mono_class_vtable || !mono_field_static_get_value) return false;
                MonoClassField* f = GetFieldPtr(klass, fieldName);
                if (!f) return false;
                DomainGuard guard(this, ActiveDomain());
                MonoVTable* vt = mono_class_vtable(ActiveDomain(), klass);
                if (!vt) return false;
                mono_field_static_get_value(vt, f, &outValue);
                return true;
            }

            template<typename T>
            bool SetStaticField(MonoClass* klass, const char* fieldName, const T& value)
            {
                if (!klass || !mono_class_vtable || !mono_field_static_set_value) return false;
                MonoClassField* f = GetFieldPtr(klass, fieldName);
                if (!f) return false;
                DomainGuard guard(this, ActiveDomain());
                MonoVTable* vt = mono_class_vtable(ActiveDomain(), klass);
                if (!vt) return false;
                mono_field_static_set_value(vt, f, (void*)&value);
                return true;
            }

            // ---- properties (get/set methods) ----
            MonoMethod* GetPropertyGetter(MonoClass* klass, const char* propName)
            {
                if (!klass || !mono_class_get_property_from_name || !mono_property_get_get_method) return nullptr;
                MonoProperty* p = mono_class_get_property_from_name(klass, propName);
                return p ? mono_property_get_get_method(p) : nullptr;
            }

            MonoMethod* GetPropertySetter(MonoClass* klass, const char* propName)
            {
                if (!klass || !mono_class_get_property_from_name || !mono_property_get_set_method) return nullptr;
                MonoProperty* p = mono_class_get_property_from_name(klass, propName);
                return p ? mono_property_get_set_method(p) : nullptr;
            }

            // ---- object creation / init ----
            MonoObject* NewObject(const char* imageSubstr, const char* nameSpace, const char* className)
            {
                if (!Attach() || !mono_object_new || !mono_runtime_object_init) return nullptr;
                MonoClass* k = GetClassPtr(imageSubstr, nameSpace, className);
                if (!k) return nullptr;

                DomainGuard guard(this, ActiveDomain());
                MonoDomain* dom = ActiveDomain();
                if (!dom) return nullptr;

                MonoObject* obj = mono_object_new(dom, k);
                if (!obj) return nullptr;
                mono_runtime_object_init(obj); // default .ctor
                return obj;
            }

            // ---- strings ----
            MonoString* NewString(const char* utf8)
            {
                if (!utf8 || !mono_string_new) return nullptr;
                DomainGuard guard(this, ActiveDomain());
                return mono_string_new(ActiveDomain(), utf8);
            }

            std::string ToUtf8(MonoString* s)
            {
                if (!s || !mono_string_to_utf8) return std::string();
                char* p = mono_string_to_utf8(s);
                if (!p) return std::string();
                std::string out = p;
                if (mono_free) mono_free(p); else CoTaskMemFree(p);
                return out;
            }

            // ---- enumeration ----
            bool ForEachMethod(MonoClass* klass, const std::function<bool(MonoMethod*)>& cb)
            {
                if (!klass || !mono_class_get_methods) return false;
                void* iter = nullptr;
                for (;;)
                {
                    MonoMethod* m = mono_class_get_methods(klass, &iter);
                    if (!m) break;
                    if (!cb(m)) return true;
                }
                return true;
            }

            bool ForEachField(MonoClass* klass, const std::function<bool(MonoClassField*)>& cb)
            {
                if (!klass || !mono_class_get_fields) return false;
                void* iter = nullptr;
                for (;;)
                {
                    MonoClassField* f = (MonoClassField*)mono_class_get_fields(klass, &iter);
                    if (!f) break;
                    if (!cb(f)) return true;
                }
                return true;
            }

            // --------------------------------------------------
            // Invoke argument pack: keeps value storage alive
            // --------------------------------------------------
            struct InvokeArgs
            {
                std::vector<std::vector<uint8_t>> storage;
                std::vector<void*>                argv;

                void clear()
                {
                    storage.clear();
                    argv.clear();
                }

                template<typename T>
                InvokeArgs& push(const T& v)
                {
                    storage.emplace_back(sizeof(T));
                    std::memcpy(storage.back().data(), &v, sizeof(T));
                    argv.push_back(storage.back().data());
                    return *this;
                }

                // Pass a managed object directly
                InvokeArgs& push_obj(MonoObject* obj)
                {
                    storage.emplace_back(sizeof(MonoObject*));
                    std::memcpy(storage.back().data(), &obj, sizeof(MonoObject*));
                    argv.push_back(storage.back().data());
                    return *this;
                }

                // Convenience for const char* → MonoString*
                InvokeArgs& push_cstr(MonoAPI* api, const char* s)
                {
                    MonoString* ms = api->NewString(s);
                    storage.emplace_back(sizeof(MonoString*));
                    std::memcpy(storage.back().data(), &ms, sizeof(MonoString*));
                    argv.push_back(storage.back().data());
                    return *this;
                }

                void** data() { return argv.empty() ? nullptr : argv.data(); }
            };

            // Low-level: invoke by MonoMethod*
            MonoObject* InvokeRaw(MonoMethod* method, MonoObject* thisObj, InvokeArgs* args, MonoObject** outException = nullptr)
            {
                if (!method || !mono_runtime_invoke)
                    return nullptr;

                DomainGuard guard(this, ActiveDomain());

                MonoObject* excLocal = nullptr;
                MonoObject* ret = mono_runtime_invoke(method, thisObj, args ? args->data() : nullptr, &excLocal);
                if (outException) *outException = excLocal;
                else if (excLocal) {
                    if (mono_object_to_string) {
                        MonoObject* toStrExc = nullptr;
                        MonoString* s = mono_object_to_string(excLocal, &toStrExc);
                        if (s) {
                            auto msg = ToUtf8(s);
                            std::printf("[MonoEasy] Invoke exception: %s\n", msg.c_str());
                        }
                        else {
                            std::printf("[MonoEasy] Invoke threw managed exception (toString failed)\n");
                        }
                    }
                    else {
                        std::printf("[MonoEasy] Invoke threw managed exception\n");
                    }
                }
                return ret;
            }

            // High-level: invoke by name (resolves method, then calls)
            MonoObject* InvokeByName(const char* imageSubstr,
                const char* nameSpace,
                const char* className,
                const char* methodName,
                int paramCount,
                MonoObject* thisObj,
                InvokeArgs* args,
                MonoObject** outException = nullptr)
            {
                MonoMethod* m = GetMethodPtr(imageSubstr, nameSpace, className, methodName, paramCount);
                if (!m) {
                    std::printf("[MonoEasy] InvokeByName: method not found %s.%s::%s\n",
                        nameSpace ? nameSpace : "", className, methodName);
                    return nullptr;
                }
                return InvokeRaw(m, thisObj, args, outException);
            }

            // Unbox helper (value types). Returns false if not a value-type box.
            template<typename T>
            bool UnboxValue(MonoObject* boxed, T& out)
            {
                if (!boxed || !mono_object_unbox) return false;
                void* p = mono_object_unbox(boxed);
                if (!p) return false;
                std::memcpy(&out, p, sizeof(T));
                return true;
            }

            // Return converters
            bool InvokeRetVoid(MonoMethod* m, MonoObject* thisObj, InvokeArgs* args, MonoObject** outExc = nullptr)
            {
                InvokeRaw(m, thisObj, args, outExc);
                return true;
            }

            template<typename T>
            bool InvokeRetValue(MonoMethod* m, MonoObject* thisObj, InvokeArgs* args, T& out, MonoObject** outExc = nullptr)
            {
                MonoObject* ret = InvokeRaw(m, thisObj, args, outExc);
                if (!ret) { std::memset(&out, 0, sizeof(T)); return true; } // void or null → zero
                return UnboxValue<T>(ret, out);
            }

            bool InvokeRetObject(MonoMethod* m, MonoObject* thisObj, InvokeArgs* args, MonoObject*& outObj, MonoObject** outExc = nullptr)
            {
                outObj = InvokeRaw(m, thisObj, args, outExc);
                return true;
            }

            bool InvokeRetString(MonoMethod* m, MonoObject* thisObj, InvokeArgs* args, std::string& outStr, MonoObject** outExc = nullptr)
            {
                outStr.clear();
                MonoObject* ret = InvokeRaw(m, thisObj, args, outExc);
                if (!ret) return true;
                auto* ms = reinterpret_cast<MonoString*>(ret);
                outStr = ToUtf8(ms);
                return true;
            }
        };

        // --------- SINGLETON & simple wrappers ---------
        inline MonoAPI& API() { static MonoAPI a; return a; }

        inline bool Init() { return API().Init(); }
        inline bool InitWithWait(DWORD timeoutMs = 8000, DWORD pollMs = 50) { return API().InitWithWait(timeoutMs, pollMs); }
        inline bool Attach() { return API().Attach(); }
        inline void CaptureCurrentDomainAsScripting() { API().CaptureCurrentDomainAsScripting(); }

        inline MonoImage* FindImage(const char* nameSubstr) { return API().FindImage(nameSubstr); }

        inline void* GetAddress(const char* imageSubstr,
            const char* nameSpace,
            const char* className,
            const char* methodName,
            int paramCount = -1)
        {
            return API().GetAddress(imageSubstr, nameSpace, className, methodName, paramCount);
        }

        inline void* GetAddressFQN(const char* spec) { return API().GetAddressFQN(spec); }

        inline MonoClass* GetClassPtr(const char* imageSubstr, const char* nameSpace, const char* className)
        {
            return API().GetClassPtr(imageSubstr, nameSpace, className);
        }

        inline MonoMethod* GetMethodPtr(const char* imageSubstr,
            const char* nameSpace,
            const char* className,
            const char* methodName,
            int paramCount = -1)
        {
            return API().GetMethodPtr(imageSubstr, nameSpace, className, methodName, paramCount);
        }

        template<typename T>
        inline bool GetInstanceField(MonoObject* obj, const char* fieldName, T& outValue)
        {
            return API().GetInstanceField<T>(obj, fieldName, outValue);
        }

        template<typename T>
        inline bool SetInstanceField(MonoObject* obj, const char* fieldName, const T& value)
        {
            return API().SetInstanceField<T>(obj, fieldName, value);
        }

        template<typename T>
        inline bool GetStaticField(MonoClass* klass, const char* fieldName, T& outValue)
        {
            return API().GetStaticField<T>(klass, fieldName, outValue);
        }

        template<typename T>
        inline bool SetStaticField(MonoClass* klass, const char* fieldName, const T& value)
        {
            return API().SetStaticField<T>(klass, fieldName, value);
        }

        inline MonoObject* NewObject(const char* imageSubstr, const char* nameSpace, const char* className)
        {
            return API().NewObject(imageSubstr, nameSpace, className);
        }

        inline MonoString* NewString(const char* utf8)
        {
            return API().NewString(utf8);
        }

        inline std::string ToUtf8(MonoString* s)
        {
            return API().ToUtf8(s);
        }

        inline MonoObject* InvokeRaw(MonoMethod* m, MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, MonoObject** outExc = nullptr)
        {
            return API().InvokeRaw(m, thisObj, args, outExc);
        }

        inline MonoObject* InvokeByName(const char* img, const char* ns, const char* cls, const char* mth, int paramCount,
            MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, MonoObject** outExc = nullptr)
        {
            return API().InvokeByName(img, ns, cls, mth, paramCount, thisObj, args, outExc);
        }

        template<typename T>
        inline bool InvokeRetValue(MonoMethod* m, MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, T& out, MonoObject** outExc = nullptr)
        {
            return API().InvokeRetValue<T>(m, thisObj, args, out, outExc);
        }

        inline bool InvokeRetVoid(MonoMethod* m, MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, MonoObject** outExc = nullptr)
        {
            return API().InvokeRetVoid(m, thisObj, args, outExc);
        }

        inline bool InvokeRetObject(MonoMethod* m, MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, MonoObject*& outObj, MonoObject** outExc = nullptr)
        {
            return API().InvokeRetObject(m, thisObj, args, outObj, outExc);
        }

        inline bool InvokeRetString(MonoMethod* m, MonoObject* thisObj, IMH::MonoEasy::MonoAPI::InvokeArgs* args, std::string& outStr, MonoObject** outExc = nullptr)
        {
            return API().InvokeRetString(m, thisObj, args, outStr, outExc);
        }

        // ---- hooking ----
        inline bool HookAt(void* addr, void* detour, void** original)
        {
            if (!addr || !detour || !original) return false;

            if (MH_CreateHook(addr, detour, original) != MH_OK)
            {
                std::printf("[MonoEasy] MH_CreateHook failed @ %p\n", addr);
                return false;
            }
            if (MH_EnableHook(addr) != MH_OK)
            {
                std::printf("[MonoEasy] MH_EnableHook failed @ %p\n", addr);
                return false;
            }
            return true;
        }
    } // namespace MonoEasy

// Convenience macros (unchanged)
#define IMH_MONO_HOOK(IMG, NS, CLS, MTH, ARGC, DETOUR_FN, ORIG_VAR, FN_TYPE)               \
    do {                                                                                    \
        void* _addr = ::IMH::MonoEasy::GetAddress((IMG), (NS), (CLS), (MTH), (ARGC));       \
        if (!_addr) { std::printf("[MonoEasy] hook target not found\n"); }                  \
        else {                                                                              \
            if (!::IMH::MonoEasy::HookAt(_addr, (LPVOID)(DETOUR_FN), (LPVOID*)&(ORIG_VAR))) \
                std::printf("[MonoEasy] hook failed\n");                                    \
            else                                                                            \
                std::printf("[MonoEasy] Hooked %s.%s::%s @ %p\n", (NS), (CLS), (MTH), _addr); \
        }                                                                                   \
    } while (0)

#define IMH_MONO_HOOK_FQN(SPEC, DETOUR_FN, ORIG_VAR, FN_TYPE)                               \
    do {                                                                                    \
        void* _addr = ::IMH::MonoEasy::GetAddressFQN((SPEC));                               \
        if (!_addr) { std::printf("[MonoEasy] hook target not found: %s\n", (SPEC)); }      \
        else {                                                                              \
            if (!::IMH::MonoEasy::HookAt(_addr, (LPVOID)(DETOUR_FN), (LPVOID*)&(ORIG_VAR))) \
                std::printf("[MonoEasy] hook failed: %s\n", (SPEC));                        \
            else                                                                            \
                std::printf("[MonoEasy] Hooked %s @ %p\n", (SPEC), _addr);                  \
        }                                                                                   \
    } while (0)

} // namespace IMH

/*
USAGE NOTES
-----------
1) Initialize & attach:
    IMH::MonoEasy::InitWithWait();
    IMH::MonoEasy::Attach();

2) In a managed detour (e.g., hooked Update/Start), call once:
    IMH::MonoEasy::CaptureCurrentDomainAsScripting();

3) Invoke example:
    auto* m = IMH::MonoEasy::GetMethodPtr("Assembly-CSharp", "", "Test", "Add", 2);
    IMH::MonoEasy::MonoAPI::InvokeArgs args;
    args.push<int32_t>(2).push<int32_t>(3);
    int32_t sum = 0;
    IMH::MonoEasy::InvokeRetValue<int32_t>(m, nullptr, &args, sum);
    std::printf("sum=%d\n", (int)sum);

4) Strings/objects/static fields are now created/accessed in the active (scripting) domain,
   so Invoke* works reliably even from your own native thread.
*/
#endif

#if _IL2CPP
#include "IL2CPP/Main.hpp"

namespace IMH
{
    namespace il2cpp
    {
        namespace Find
        {
            inline Unity::il2cppArray<Unity::CGameObject*>* f_GetObjectArrayOfType(const char* Id)
            {
                Unity::il2cppArray<Unity::CGameObject*>* Objects = Unity::Object::FindObjectsOfType<Unity::CGameObject>(Id);

                return Objects;
            }

            inline Unity::CGameObject* f_GetObject(const char* Id)
            {
                Unity::CGameObject* Object = Unity::GameObject::Find(Id);

                return Object;
            }

            inline Unity::CGameObject* f_BruteForceSearch(std::string name)
            {
                auto List = f_GetObjectArrayOfType("UnityEngine.GameObject");

                for (int i = 0; i < List->m_uMaxLength; i++)
                {
                    auto object = List->At(i);
                    if (object->GetName()->ToString() == name.c_str())
                    {
                        return reinterpret_cast<Unity::CGameObject*>(object);
                    }
                }
                return nullptr;
            }
        }

        namespace Functions
        {
            // IL2CPP::Class::Utils::GetMethodPointer("ScheduleOne.PlayerScripts.Player", "set_IsTased");
            /* 
            Example: "ScheduleOne.PlayerScripts.Player", "set_IsTased"
            Example: "BasicSample", "OnGui"

			Basically the class name or full namespace + class name, and the method name.
			See example picture in the folder for reference.
            */
            inline void* f_GetMethodPointer(const char* className, const char* methodName)
            {
				return IL2CPP::Class::Utils::GetMethodPointer(className, methodName);
            }
        }
	}
}
#endif