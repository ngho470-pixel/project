PG_CONFIG := pg_config

CC       := gcc
CXX      := g++
CFLAGS   := -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags)
CXXFLAGS := -std=c++17 -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags)
INCLUDES := -I$(shell $(PG_CONFIG) --includedir-server) -I$(CURDIR)/../cvc5/include -I$(CURDIR)/../cvc5/build/include -I$(CURDIR)/cvc5/include -I$(CURDIR)/cvc5/build/include

# Ensure the packaged runtime can resolve cvc5 dependencies from a sibling `lib/`
# directory (e.g. /tmp/z3_lab/custom_filter.so + /tmp/z3_lab/lib/libcvc5.so.1).
# NOTE: We intentionally force DT_RPATH (not DT_RUNPATH) so that `$ORIGIN/lib`
# is inherited and applies to libcvc5's transitive deps (e.g. libcln).
LDFLAGS  := -Wl,--disable-new-dtags -Wl,-rpath,'$$ORIGIN/lib' -Wl,-z,origin

CVC5_LIBS := $(CURDIR)/lib/libcvc5.so.1
EXTRA_SOLVER_LIBS :=
ifneq ($(wildcard $(CURDIR)/lib/libpoly.so.0),)
EXTRA_SOLVER_LIBS += $(CURDIR)/lib/libpoly.so.0
endif
ifneq ($(wildcard $(CURDIR)/lib/libpolyxx.so.0),)
EXTRA_SOLVER_LIBS += $(CURDIR)/lib/libpolyxx.so.0
endif

TARGET  := custom_filter.so
OBJS    := custom_filter.o policy.o policy_evaluator.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS) $(CVC5_LIBS) -Wl,--no-as-needed $(EXTRA_SOLVER_LIBS) -Wl,--as-needed

custom_filter.o: custom_filter.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

policy.o: policy.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

policy_evaluator.o: policy_evaluator.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
