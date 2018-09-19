#CXX = /Library/Developer/CommandLineTools/usr/bin/clang
CXX = /usr/local/bin/clang

CXXFLAGS = -I$(SRCDIR) -MMD
CXXFLAGS += -std=c++1z
CXXFLAGS +=  -Wextra
CXXFLAGS +=  -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-c++98-c++11-compat-binary-literal -Wno-padded -Wno-reserved-id-macro
CXXFLAGS += -nostdinc++ -I/usr/local/include/c++/v1
CXXFLAGS += -DNDEBUG=1 #-O3

LDFLAGS = -nostdlib
LDFLAGS += -L/usr/lib
LDFLAGS += -L/usr/local/lib
LDFLAGS += -lc++ -lSystem -lcrypto

SRCDIR = src

TESTDIR = test

OBJDIR = obj

BINDIR = bin

LIBDIR = lib

INCDIR = include

GTESTDIR = ../googletest/googletest


TARGETS = $(addprefix $(BINDIR)/, example benchmark)

MAINS	= $(TARGETS:$(BINDIR)/%=$(SRCDIR)/%.cpp)

SOURCES = $(filter-out $(MAINS), $(wildcard $(SRCDIR)/*.cpp $(SRCDIR)/*/*.cpp $(SRCDIR)/*/*/*.cpp))

OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGETS): $(OBJECTS)
	@mkdir -p $(BINDIR)
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(@:$(BINDIR)/%=$(SRCDIR)/%.cpp) $(OBJECTS) -MF $(@:$(BINDIR)/%=$(OBJDIR)/%.d) -o $@

# LIBRARIES = $(addprefix $(LIBDIR)/, libnet4cpp.a)
#
# $(LIBRARIES) : $(OBJECTS)
# 	@mkdir -p $(@D)
# 	$(AR) $(ARFLAGS) $@ $^

HEADERS = $(wildcard $(SRCDIR)/*.hpp $(SRCDIR)/*/*.hpp $(SRCDIR)/*/*/*.hpp)

INCLUDES = $(HEADERS:$(SRCDIR)/%.hpp=$(INCDIR)/%.hpp)

$(INCDIR)/%.hpp: $(SRCDIR)/%.hpp
	@mkdir -p $(@D)
	cp $< $@


GTEST_TARGET = $(BINDIR)/test

GTESTLIB = $(GTESTDIR)/make/gtest_main.a

GTEST_SOURCES = $(wildcard $(TESTDIR)/*.cpp $(TESTDIR)/*/*.cpp $(TESTDIR)/*/*/*.cpp $(TESTDIR)/*/*/*/*.cp)

GTEST_OBJECTS = $(GTEST_SOURCES:$(TESTDIR)/%.cpp=$(OBJDIR)/$(TESTDIR)/%.o)

$(OBJDIR)/$(TESTDIR)/%.o: $(TESTDIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) -I$(GTESTDIR)/include/ --system-header-prefix=gtest $(CXXFLAGS) -c $< -o $@

$(GTEST_TARGET): $(OBJECTS) $(GTEST_OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(GTEST_OBJECTS) $(GTESTLIB) -o $@


DEPENDENCIES = $(MAINS:$(SRCDIR)/%.cpp=$(OBJDIR)/%.d) $(OBJECTS:%.o=%.d) $(GTEST_OBJECTS:%.o=%.d)

.PHONY: bin
bin: $(TARGETS)

.PHONY: lib
lib: $(LIBRARIES) $(INCLUDES)

.PHONY: test
test: $(GTEST_TARGET)
	$(GTEST_TARGET)

.PHONY: all
all: $(TARGETS) $(LIBRARIES) $(GTEST_TARGET)

.PHONY: clean
clean:
	@rm -rf $(OBJDIR)
	@rm -rf $(BINDIR)
	@rm -rf $(LIBDIR)
	@rm -rf $(INCDIR)

.PHONY: dump
dump:
	@echo $(TARGETS)
	@echo $(MAINS)
	@echo $(SOURCES)
	@echo $(OBJECTS)
	@echo $(LIBRARIES)
	@echo $(HEADERS)
	@echo $(INCLUDES)
	@echo $(GTEST_TARGET)
	@echo $(GTEST_SOURCES)
	@echo $(GTEST_OBJECTS)
	@echo $(DEPENDENCIES)

-include $(DEPENDENCIES)
