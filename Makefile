ALL = instrument.so simulate
all: ${ALL}

instrument.so: instrument.cc
	$(CXX) -shared -MMD -o $@ $<

simulate: simulate.cc
	$(CXX) -MMD -ggdb -o $@ $< -lcapstone -lglib-2.0

clean:
	rm -f ${ALL}
	rm -f *.d

-include $(patsubst %.cc,%.d,$(wildcard *.cc))
