PG_CONFIG := pg_config

CC       := gcc
CXX      := g++
CFLAGS   := -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags)
CXXFLAGS := -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags)
INCLUDES := -I$(shell $(PG_CONFIG) --includedir-server)

# Ensure the packaged runtime can resolve cvc5 dependencies from a sibling `lib/`
# directory (e.g. /tmp/z3_lab/custom_filter.so + /tmp/z3_lab/lib/libcvc5.so.1).
# NOTE: We intentionally force DT_RPATH (not DT_RUNPATH) so that `$ORIGIN/lib`
# is inherited and applies to libcvc5's transitive deps (e.g. libcln).
LDFLAGS  := -Wl,--disable-new-dtags -Wl,-rpath,'$$ORIGIN/lib' -Wl,-z,origin

CVC5_LIBS := -lcvc5

TARGET  := custom_filter.so
OBJS    := custom_filter.o policy.o policy_evaluator.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS) $(CVC5_LIBS)

custom_filter.o: custom_filter.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

policy.o: policy.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

policy_evaluator.o: policy_evaluator.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
