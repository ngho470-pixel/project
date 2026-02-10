PG_CONFIG := pg_config

CC       := gcc
CXX      := g++
CFLAGS   := -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags) -Wno-declaration-after-statement
CXXFLAGS := -fPIC -Wall -Wextra -O2 $(shell $(PG_CONFIG) --cflags)
INCLUDES := -I$(shell $(PG_CONFIG) --includedir-server)

TARGET  := artifact_builder.so
OBJS    := artifact_builder.o artifact_builder_helper.o policy_spec.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $^

artifact_builder.o: artifact_builder.c artifact_builder.hpp policy_spec.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

artifact_builder_helper.o: artifact_builder_helper.cpp artifact_builder.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

policy_spec.o: policy_spec.c policy_spec.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
