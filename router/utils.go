package router

func isQUICPacket(firstByte byte) bool {
	return firstByte&0x40 > 0
}

// isLongHeaderPacket says if this is a Long Header packet
func isLongHeaderPacket(firstByte byte) bool {
	return firstByte&0x80 > 0
}
